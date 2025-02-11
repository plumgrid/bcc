/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
// Copyright (c) 2020 Wenbo Zhang
//
// Based on ksyms improvements from Andrii Nakryiko, add more helpers.
// 28-Feb-2020   Wenbo Zhang   Created this.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <time.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <limits.h>
#include "trace_helpers.h"
#include "uprobe_helpers.h"

#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })

#define DISK_NAME_LEN	32

#define MINORBITS	20
#define MINORMASK	((1U << MINORBITS) - 1)

#define MKDEV(ma, mi)	(((ma) << MINORBITS) | (mi))

struct ksyms {
	struct ksym *syms;
	int syms_sz;
	int syms_cap;
	char *strs;
	int strs_sz;
	int strs_cap;
};

static int ksyms__add_symbol(struct ksyms *ksyms, const char *name, unsigned long addr)
{
	size_t new_cap, name_len = strlen(name) + 1;
	struct ksym *ksym;
	void *tmp;

	if (ksyms->strs_sz + name_len > ksyms->strs_cap) {
		new_cap = ksyms->strs_cap * 4 / 3;
		if (new_cap < ksyms->strs_sz + name_len)
			new_cap = ksyms->strs_sz + name_len;
		if (new_cap < 1024)
			new_cap = 1024;
		tmp = realloc(ksyms->strs, new_cap);
		if (!tmp)
			return -1;
		ksyms->strs = tmp;
		ksyms->strs_cap = new_cap;
	}
	if (ksyms->syms_sz + 1 > ksyms->syms_cap) {
		new_cap = ksyms->syms_cap * 4 / 3;
		if (new_cap < 1024)
			new_cap = 1024;
		tmp = realloc(ksyms->syms, sizeof(*ksyms->syms) * new_cap);
		if (!tmp)
			return -1;
		ksyms->syms = tmp;
		ksyms->syms_cap = new_cap;
	}

	ksym = &ksyms->syms[ksyms->syms_sz];
	/* while constructing, re-use pointer as just a plain offset */
	ksym->name = (void *)(unsigned long)ksyms->strs_sz;
	ksym->addr = addr;

	memcpy(ksyms->strs + ksyms->strs_sz, name, name_len);
	ksyms->strs_sz += name_len;
	ksyms->syms_sz++;

	return 0;
}

static int ksym_cmp(const void *p1, const void *p2)
{
	const struct ksym *s1 = p1, *s2 = p2;

	if (s1->addr == s2->addr)
		return strcmp(s1->name, s2->name);
	return s1->addr < s2->addr ? -1 : 1;
}

struct ksyms *ksyms__load(void)
{
	char sym_type, sym_name[256];
	struct ksyms *ksyms;
	unsigned long sym_addr;
	int i, ret;
	FILE *f;

	f = fopen("/proc/kallsyms", "r");
	if (!f)
		return NULL;

	ksyms = calloc(1, sizeof(*ksyms));
	if (!ksyms)
		goto err_out;

	while (true) {
		ret = fscanf(f, "%lx %c %s%*[^\n]\n",
			     &sym_addr, &sym_type, sym_name);
		if (ret == EOF && feof(f))
			break;
		if (ret != 3)
			goto err_out;
		if (ksyms__add_symbol(ksyms, sym_name, sym_addr))
			goto err_out;
	}

	/* now when strings are finalized, adjust pointers properly */
	for (i = 0; i < ksyms->syms_sz; i++)
		ksyms->syms[i].name += (unsigned long)ksyms->strs;

	qsort(ksyms->syms, ksyms->syms_sz, sizeof(*ksyms->syms), ksym_cmp);

	fclose(f);
	return ksyms;

err_out:
	ksyms__free(ksyms);
	fclose(f);
	return NULL;
}

void ksyms__free(struct ksyms *ksyms)
{
	if (!ksyms)
		return;

	free(ksyms->syms);
	free(ksyms->strs);
	free(ksyms);
}

const struct ksym *ksyms__map_addr(const struct ksyms *ksyms,
				   unsigned long addr)
{
	int start = 0, end = ksyms->syms_sz - 1, mid;
	unsigned long sym_addr;

	/* find largest sym_addr <= addr using binary search */
	while (start < end) {
		mid = start + (end - start + 1) / 2;
		sym_addr = ksyms->syms[mid].addr;

		if (sym_addr <= addr)
			start = mid;
		else
			end = mid - 1;
	}

	if (start == end && ksyms->syms[start].addr <= addr)
		return &ksyms->syms[start];
	return NULL;
}

const struct ksym *ksyms__get_symbol(const struct ksyms *ksyms,
				     const char *name)
{
	int i;

	for (i = 0; i < ksyms->syms_sz; i++) {
		if (strcmp(ksyms->syms[i].name, name) == 0)
			return &ksyms->syms[i];
	}

	return NULL;
}

struct load_range {
	uint64_t start;
	uint64_t end;
	uint64_t file_off;
};

enum elf_type {
	EXEC,
	DYN,
	PERF_MAP,
	VDSO,
	UNKNOWN,
};

struct dso {
	char *name;
	pid_t tgid;
	struct load_range *ranges;
	int range_sz;
	/* Dyn's first text section virtual addr at execution */
	uint64_t sh_addr;
	/* Dyn's first text section file offset */
	uint64_t sh_offset;
	enum elf_type type;

	struct sym *syms;
	int syms_sz;
	int syms_cap;

	/*
	 * libbpf's struct btf is actually a pretty efficient
	 * "set of strings" data structure, so we create an
	 * empty one and use it to store symbol names.
	 */
	struct btf *btf;
};

struct map {
	uint64_t start_addr;
	uint64_t end_addr;
	uint64_t file_off;
	uint64_t dev_major;
	uint64_t dev_minor;
	uint64_t inode;
};

struct syms {
	struct dso *dsos;
	int dso_sz;
};

const char* elf_type_to_string(enum elf_type type) {
    switch (type) {
        case EXEC:
            return "EXEC";
        case DYN:
            return "DYN";
        case PERF_MAP:
            return "PERF_MAP";
        case VDSO:
            return "VDSO";
        case UNKNOWN:
            return "UNKNOWN";
        default:
            return "INVALID";
    }
}

static bool is_file_backed(const char *mapname)
{
#define STARTS_WITH(mapname, prefix) \
	(!strncmp(mapname, prefix, sizeof(prefix) - 1))

	return mapname[0] && !(
		STARTS_WITH(mapname, "//anon") ||
		STARTS_WITH(mapname, "/dev/zero") ||
		STARTS_WITH(mapname, "/anon_hugepage") ||
		STARTS_WITH(mapname, "[stack") ||
		STARTS_WITH(mapname, "/SYSV") ||
		STARTS_WITH(mapname, "[heap]") ||
		STARTS_WITH(mapname, "[uprobes]") ||
		STARTS_WITH(mapname, "[vsyscall]"));
}

static bool is_perf_map(const char *path)
{
	return false;
}

static bool is_vdso(const char *path)
{
	return !strcmp(path, "[vdso]");
}

static bool is_uprobes(const char *path)
{
	return !strcmp(path, "[uprobes]");
}

static int get_elf_type(const char *path)
{
	GElf_Ehdr hdr;
	void *res;
	Elf *e;
	int fd;

	if (is_vdso(path))
		return -1;
	if (is_uprobes(path))
		return -1;
	e = open_elf(path, &fd);
	if (!e)
		return -1;
	res = gelf_getehdr(e, &hdr);
	close_elf(e, fd);
	if (!res)
		return -1;
	return hdr.e_type;
}

static int get_elf_text_scn_info(const char *path, uint64_t *addr,
				 uint64_t *offset)
{
	Elf_Scn *section = NULL;
	int fd = -1, err = -1;
	GElf_Shdr header;
	size_t stridx;
	Elf *e = NULL;
	char *name;

	e = open_elf(path, &fd);
	if (!e)
		goto err_out;
	err = elf_getshdrstrndx(e, &stridx);
	if (err < 0)
		goto err_out;

	err = -1;
	while ((section = elf_nextscn(e, section)) != 0) {
		if (!gelf_getshdr(section, &header))
			continue;

		name = elf_strptr(e, stridx, header.sh_name);
		if (name && !strcmp(name, ".text")) {
			*addr = (uint64_t)header.sh_addr;
			*offset = (uint64_t)header.sh_offset;
			err = 0;
			break;
		}
	}

err_out:
	close_elf(e, fd);
	return err;
}

static int syms__add_dso(struct syms *syms, struct map *map, const char *name, pid_t tgid)
{
	struct dso *dso = NULL;
	int i, type;
	void *tmp;

	for (i = 0; i < syms->dso_sz; i++) {
		if (!strcmp(syms->dsos[i].name, name)) {
			dso = &syms->dsos[i];
			break;
		}
	}

	if (!dso) {
		tmp = realloc(syms->dsos, (syms->dso_sz + 1) *
			      sizeof(*syms->dsos));
		if (!tmp)
			return -1;
		syms->dsos = tmp;
		dso = &syms->dsos[syms->dso_sz++];
		memset(dso, 0, sizeof(*dso));
		dso->name = strdup(name);
		dso->btf = btf__new_empty();
	}

	tmp = realloc(dso->ranges, (dso->range_sz + 1) * sizeof(*dso->ranges));
	if (!tmp)
		return -1;
	dso->tgid = tgid;
	dso->ranges = tmp;
	dso->ranges[dso->range_sz].start = map->start_addr;
	dso->ranges[dso->range_sz].end = map->end_addr;
	dso->ranges[dso->range_sz].file_off = map->file_off;
	dso->range_sz++;
	type = get_elf_type(name);
	if (type == ET_EXEC) {
		dso->type = EXEC;
	} else if (type == ET_DYN) {
		dso->type = DYN;
		if (get_elf_text_scn_info(name, &dso->sh_addr, &dso->sh_offset) < 0)
			return -1;
	} else if (is_perf_map(name)) {
		dso->type = PERF_MAP;
	} else if (is_vdso(name)) {
		dso->type = VDSO;
	} else {
		dso->type = UNKNOWN;
	}
	return 0;
}

static struct dso *syms__find_dso(const struct syms *syms, unsigned long addr,
				  uint64_t *offset)
{
	struct load_range *range;
	struct dso *dso;
	int i, j;

	for (i = 0; i < syms->dso_sz; i++) {
		dso = &syms->dsos[i];
		for (j = 0; j < dso->range_sz; j++) {
			range = &dso->ranges[j];
			if (addr <= range->start || addr >= range->end)
				continue;
			if (dso->type == DYN || dso->type == VDSO) {
				/* Offset within the mmap */
				*offset = addr - range->start + range->file_off;
				/* Offset within the ELF for dyn symbol lookup */
				*offset += dso->sh_addr - dso->sh_offset;
			} else {
				*offset = addr;
			}

			return dso;
		}
	}

	return NULL;
}

static int dso__load_sym_table_from_perf_map(struct dso *dso)
{
	return -1;
}

static int dso__add_sym(struct dso *dso, const char *name, uint64_t start,
			uint64_t size)
{
	struct sym *sym;
	size_t new_cap;
	void *tmp;
	int off;

	off = btf__add_str(dso->btf, name);
	if (off < 0)
		return off;

	if (dso->syms_sz + 1 > dso->syms_cap) {
		new_cap = dso->syms_cap * 4 / 3;
		if (new_cap < 1024)
			new_cap = 1024;
		tmp = realloc(dso->syms, sizeof(*dso->syms) * new_cap);
		if (!tmp)
			return -1;
		dso->syms = tmp;
		dso->syms_cap = new_cap;
	}

	sym = &dso->syms[dso->syms_sz++];
	/* while constructing, re-use pointer as just a plain offset */
	sym->name = (void*)(unsigned long)off;
	sym->start = start;
	sym->size = size;
	sym->offset = 0;

	return 0;
}

static int sym_cmp(const void *p1, const void *p2)
{
	const struct sym *s1 = p1, *s2 = p2;

	if (s1->start == s2->start)
		return strcmp(s1->name, s2->name);
	return s1->start < s2->start ? -1 : 1;
}

static int dso__add_syms(struct dso *dso, Elf *e, Elf_Scn *section,
			 size_t stridx, size_t symsize)
{
	Elf_Data *data = NULL;

	while ((data = elf_getdata(section, data)) != 0) {
		size_t i, symcount = data->d_size / symsize;

		if (data->d_size % symsize)
			return -1;

		for (i = 0; i < symcount; ++i) {
			const char *name;
			GElf_Sym sym;

			if (!gelf_getsym(data, (int)i, &sym))
				continue;
			if (!(name = elf_strptr(e, stridx, sym.st_name)))
				continue;
			if (name[0] == '\0')
				continue;

			if (sym.st_value == 0)
				continue;

			if (dso__add_sym(dso, name, sym.st_value, sym.st_size))
				goto err_out;
		}
	}

	return 0;

err_out:
	return -1;
}

static void dso__free_fields(struct dso *dso)
{
	if (!dso)
		return;

	free(dso->name);
	free(dso->ranges);
	free(dso->syms);
	btf__free(dso->btf);
}

static int dso__load_sym_table_from_elf(struct dso *dso, int fd)
{
	Elf_Scn *section = NULL;
	Elf *e;
	int i;

	e = fd > 0 ? open_elf_by_fd(fd) : open_elf(dso->name, &fd);
	if (!e)
		return -1;

	while ((section = elf_nextscn(e, section)) != 0) {
		GElf_Shdr header;

		if (!gelf_getshdr(section, &header))
			continue;

		if (header.sh_type != SHT_SYMTAB &&
		    header.sh_type != SHT_DYNSYM)
			continue;

		if (dso__add_syms(dso, e, section, header.sh_link,
				  header.sh_entsize))
			goto err_out;
	}

	/* now when strings are finalized, adjust pointers properly */
	for (i = 0; i < dso->syms_sz; i++)
		dso->syms[i].name =
			btf__name_by_offset(dso->btf,
					    (unsigned long)dso->syms[i].name);

	qsort(dso->syms, dso->syms_sz, sizeof(*dso->syms), sym_cmp);

	close_elf(e, fd);
	return 0;

err_out:
	dso__free_fields(dso);
	close_elf(e, fd);
	return -1;
}

static int create_tmp_vdso_image(struct dso *dso)
{
	uint64_t start_addr, end_addr;
	long pid = getpid();
	char buf[PATH_MAX];
	void *image = NULL;
	char tmpfile[128];
	int ret, fd = -1;
	uint64_t sz;
	char *name;
	FILE *f;

	snprintf(tmpfile, sizeof(tmpfile), "/proc/%ld/maps", pid);
	f = fopen(tmpfile, "r");
	if (!f)
		return -1;

	while (true) {
		ret = fscanf(f, "%llx-%llx %*s %*x %*x:%*x %*u%[^\n]",
			     (long long*)&start_addr, (long long*)&end_addr,
			     buf);
		if (ret == EOF && feof(f))
			break;
		if (ret != 3)
			goto err_out;

		name = buf;
		while (isspace(*name))
			name++;
		if (!is_file_backed(name))
			continue;
		if (is_vdso(name))
			break;
	}

	sz = end_addr - start_addr;
	image = malloc(sz);
	if (!image)
		goto err_out;
	memcpy(image, (void *)start_addr, sz);

	snprintf(tmpfile, sizeof(tmpfile),
		 "/tmp/libbpf_%ld_vdso_image_XXXXXX", pid);
	fd = mkostemp(tmpfile, O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "failed to create temp file: %s\n",
			strerror(errno));
		goto err_out;
	}
	/* Unlink the file to avoid leaking */
	if (unlink(tmpfile) == -1)
		fprintf(stderr, "failed to unlink %s: %s\n", tmpfile,
			strerror(errno));
	if (write(fd, image, sz) == -1) {
		fprintf(stderr, "failed to write to vDSO image: %s\n",
			strerror(errno));
		close(fd);
		fd = -1;
		goto err_out;
	}

err_out:
	fclose(f);
	free(image);
	return fd;
}

static int dso__load_sym_table_from_vdso_image(struct dso *dso)
{
	int fd = create_tmp_vdso_image(dso);

	if (fd < 0)
		return -1;
	return dso__load_sym_table_from_elf(dso, fd);
}

static int dso__load_sym_table(struct dso *dso)
{
	if (dso->type == UNKNOWN)
		return -1;
	if (dso->type == PERF_MAP)
		return dso__load_sym_table_from_perf_map(dso);
	if (dso->type == EXEC || dso->type == DYN)
		return dso__load_sym_table_from_elf(dso, 0);
	if (dso->type == VDSO)
		return dso__load_sym_table_from_vdso_image(dso);
	return -1;
}

static struct sym *dso__find_sym(struct dso *dso, uint64_t offset)
{
	unsigned long sym_addr;
	int start, end, mid;

	if (!dso->syms && dso__load_sym_table(dso))
		return NULL;

	start = 0;
	end = dso->syms_sz - 1;

	/* find largest sym_addr <= addr using binary search */
	while (start < end) {
		mid = start + (end - start + 1) / 2;
		sym_addr = dso->syms[mid].start;

		if (sym_addr <= offset)
			start = mid;
		else
			end = mid - 1;
	}

	if (start == end && dso->syms[start].start <= offset &&
	    offset < dso->syms[start].start + dso->syms[start].size) {
		(dso->syms[start]).offset = offset - dso->syms[start].start;
		return &dso->syms[start];
	}
	return NULL;
}

struct syms *syms__load_file(const char *fname, pid_t tgid)
{
	char buf[PATH_MAX], perm[5];
	struct syms *syms;
	struct map map;
	char *name;
	FILE *f;
	int ret;

	f = fopen(fname, "r");
	if (!f)
		return NULL;

	syms = calloc(1, sizeof(*syms));
	if (!syms)
		goto err_out;

	while (true) {
		ret = fscanf(f, "%llx-%llx %4s %llx %llx:%llx %llu%[^\n]",
			     (long long*)&map.start_addr,
			     (long long*)&map.end_addr, perm,
			     (long long*)&map.file_off,
			     (long long*)&map.dev_major,
			     (long long*)&map.dev_minor,
			     (long long*)&map.inode, buf);
		if (ret == EOF && feof(f))
			break;
		if (ret != 8)	/* perf-<PID>.map */
			goto err_out;

		if (perm[2] != 'x')
			continue;

		name = buf;
		while (isspace(*name))
			name++;
		if (!is_file_backed(name))
			continue;

		if (syms__add_dso(syms, &map, name, tgid))
			goto err_out;
	}

	fclose(f);
	return syms;

err_out:
	syms__free(syms);
	fclose(f);
	return NULL;
}

struct syms *syms__load_pid(pid_t tgid)
{
	char fname[128];

	snprintf(fname, sizeof(fname), "/proc/%ld/maps", (long)tgid);
	return syms__load_file(fname, tgid);
}

void syms__free(struct syms *syms)
{
	int i;

	if (!syms)
		return;

	for (i = 0; i < syms->dso_sz; i++)
		dso__free_fields(&syms->dsos[i]);
	free(syms->dsos);
	free(syms);
}

const struct sym *syms__map_addr(const struct syms *syms, unsigned long addr)
{
	struct dso *dso;
	uint64_t offset;

	dso = syms__find_dso(syms, addr, &offset);
	if (!dso)
		return NULL;
	return dso__find_sym(dso, offset);
}

int syms__map_addr_dso(const struct syms *syms, unsigned long addr,
		       struct sym_info *sinfo)
{
	struct dso *dso;
	struct sym *sym;
	uint64_t offset;

	memset(sinfo, 0x0, sizeof(struct sym_info));

	dso = syms__find_dso(syms, addr, &offset);
	if (!dso)
		return -1;

	sinfo->dso_name = dso->name;
	sinfo->dso_offset = offset;

	sym = dso__find_sym(dso, offset);
	if (sym) {
		sinfo->sym_name = sym->name;
		sinfo->sym_offset = sym->offset;
	}

	return 0;
}

struct syms_cache {
	struct {
		struct syms *syms;
		int tgid;
	} *data;
	int nr;
};

struct syms_cache *syms_cache__new(int nr)
{
	struct syms_cache *syms_cache;

	syms_cache = calloc(1, sizeof(*syms_cache));
	if (!syms_cache)
		return NULL;
	if (nr > 0)
		syms_cache->data = calloc(nr, sizeof(*syms_cache->data));
	return syms_cache;
}

void syms_cache__free(struct syms_cache *syms_cache)
{
	int i;

	if (!syms_cache)
		return;

	for (i = 0; i < syms_cache->nr; i++)
		syms__free(syms_cache->data[i].syms);
	free(syms_cache->data);
	free(syms_cache);
}

struct syms *syms_cache__get_syms(struct syms_cache *syms_cache, int tgid)
{
	void *tmp;
	int i;

	for (i = 0; i < syms_cache->nr; i++) {
		if (syms_cache->data[i].tgid == tgid)
			return syms_cache->data[i].syms;
	}

	tmp = realloc(syms_cache->data, (syms_cache->nr + 1) *
		      sizeof(*syms_cache->data));
	if (!tmp)
		return NULL;
	syms_cache->data = tmp;
	syms_cache->data[syms_cache->nr].syms = syms__load_pid(tgid);
	syms_cache->data[syms_cache->nr].tgid = tgid;
	return syms_cache->data[syms_cache->nr++].syms;
}

struct partitions {
	struct partition *items;
	int sz;
};

static int partitions__add_partition(struct partitions *partitions,
				     const char *name, unsigned int dev)
{
	struct partition *partition;
	void *tmp;

	tmp = realloc(partitions->items, (partitions->sz + 1) *
		sizeof(*partitions->items));
	if (!tmp)
		return -1;
	partitions->items = tmp;
	partition = &partitions->items[partitions->sz];
	partition->name = strdup(name);
	partition->dev = dev;
	partitions->sz++;

	return 0;
}

struct partitions *partitions__load(void)
{
	char part_name[DISK_NAME_LEN];
	unsigned int devmaj, devmin;
	unsigned long long nop;
	struct partitions *partitions;
	char buf[64];
	FILE *f;

	f = fopen("/proc/partitions", "r");
	if (!f)
		return NULL;

	partitions = calloc(1, sizeof(*partitions));
	if (!partitions)
		goto err_out;

	while (fgets(buf, sizeof(buf), f) != NULL) {
		/* skip heading */
		if (buf[0] != ' ' || buf[0] == '\n')
			continue;
		if (sscanf(buf, "%u %u %llu %s", &devmaj, &devmin, &nop,
				part_name) != 4)
			goto err_out;
		if (partitions__add_partition(partitions, part_name,
						MKDEV(devmaj, devmin)))
			goto err_out;
	}

	fclose(f);
	return partitions;

err_out:
	partitions__free(partitions);
	fclose(f);
	return NULL;
}

void partitions__free(struct partitions *partitions)
{
	int i;

	if (!partitions)
		return;

	for (i = 0; i < partitions->sz; i++)
		free(partitions->items[i].name);
	free(partitions->items);
	free(partitions);
}

const struct partition *
partitions__get_by_dev(const struct partitions *partitions, unsigned int dev)
{
	int i;

	for (i = 0; i < partitions->sz; i++) {
		if (partitions->items[i].dev == dev)
			return &partitions->items[i];
	}

	return NULL;
}

const struct partition *
partitions__get_by_name(const struct partitions *partitions, const char *name)
{
	int i;

	for (i = 0; i < partitions->sz; i++) {
		if (strcmp(partitions->items[i].name, name) == 0)
			return &partitions->items[i];
	}

	return NULL;
}

static void print_stars(unsigned int val, unsigned int val_max, int width)
{
	int num_stars, num_spaces, i;
	bool need_plus;

	num_stars = min(val, val_max) * width / val_max;
	num_spaces = width - num_stars;
	need_plus = val > val_max;

	for (i = 0; i < num_stars; i++)
		printf("*");
	for (i = 0; i < num_spaces; i++)
		printf(" ");
	if (need_plus)
		printf("+");
}

static void print_dso_info(int fd, struct dso *dso) {
	dprintf(fd, "path = \"%s\", pid = %ld, ranges = [", dso->name, (long)dso->tgid);

	for (int i = 0; i < dso->range_sz; i++) {
		struct load_range *range = &dso->ranges[i];
		dprintf(fd, "{start = 0x%lx, end = 0x%lx, file_off = 0x%lx}",
				range->start, range->end, range->file_off);
		if (i < dso->range_sz - 1) {
			dprintf(fd, ", ");
		}
	}
	dprintf(fd, "], range_sz = %d, sh_addr = 0x%lx, sh_offset = 0x%lx, type = %s\n",
			dso->range_sz, dso->sh_addr, dso->sh_offset, elf_type_to_string(dso->type));
}

void print_dsos_info(int fd, struct syms_cache *syms_cache) {
	for (int i = 0; i < syms_cache->nr; i++) {
		struct syms *syms = syms_cache->data[i].syms;
		if (!syms)
			continue;
		for (int j = 0; j < syms->dso_sz; j++) {
			print_dso_info(fd, &syms->dsos[j]);
		}
	}
}

void print_log2_hist(unsigned int *vals, int vals_size, const char *val_type)
{
	int stars_max = 40, idx_max = -1;
	unsigned int val, val_max = 0;
	unsigned long long low, high;
	int stars, width, i;

	for (i = 0; i < vals_size; i++) {
		val = vals[i];
		if (val > 0)
			idx_max = i;
		if (val > val_max)
			val_max = val;
	}

	if (idx_max < 0)
		return;

	printf("%*s%-*s : count    distribution\n", idx_max <= 32 ? 5 : 15, "",
		idx_max <= 32 ? 19 : 29, val_type);

	if (idx_max <= 32)
		stars = stars_max;
	else
		stars = stars_max / 2;

	for (i = 0; i <= idx_max; i++) {
		low = (1ULL << (i + 1)) >> 1;
		high = (1ULL << (i + 1)) - 1;
		if (low == high)
			low -= 1;
		val = vals[i];
		width = idx_max <= 32 ? 10 : 20;
		printf("%*lld -> %-*lld : %-8d |", width, low, width, high, val);
		print_stars(val, val_max, stars);
		printf("|\n");
	}
}

void print_linear_hist(unsigned int *vals, int vals_size, unsigned int base,
		       unsigned int step, const char *val_type)
{
	int i, stars_max = 40, idx_min = -1, idx_max = -1;
	unsigned int val, val_max = 0;

	for (i = 0; i < vals_size; i++) {
		val = vals[i];
		if (val > 0) {
			idx_max = i;
			if (idx_min < 0)
				idx_min = i;
		}
		if (val > val_max)
			val_max = val;
	}

	if (idx_max < 0)
		return;

	printf("     %-13s : count     distribution\n", val_type);
	for (i = idx_min; i <= idx_max; i++) {
		val = vals[i];
		if (!val)
			continue;
		printf("        %-10d : %-8d |", base + i * step, val);
		print_stars(val, val_max, stars_max);
		printf("|\n");
	}
}

unsigned long long get_ktime_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;
}

bool is_kernel_module(const char *name)
{
	bool found = false;
	char buf[64];
	FILE *f;

	f = fopen("/proc/modules", "r");
	if (!f)
		return false;

	while (fgets(buf, sizeof(buf), f) != NULL) {
		if (sscanf(buf, "%s %*s\n", buf) != 1)
			break;
		if (!strcmp(buf, name)) {
			found = true;
			break;
		}
	}

	fclose(f);
	return found;
}

static bool fentry_try_attach(int id)
{
	int prog_fd, attach_fd;
	char error[4096];
	struct bpf_insn insns[] = {
		{ .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 0 },
		{ .code = BPF_JMP | BPF_EXIT },
	};
	LIBBPF_OPTS(bpf_prog_load_opts, opts,
			.expected_attach_type = BPF_TRACE_FENTRY,
			.attach_btf_id = id,
			.log_buf = error,
			.log_size = sizeof(error),
	);

	prog_fd = bpf_prog_load(BPF_PROG_TYPE_TRACING, "test", "GPL", insns,
			sizeof(insns) / sizeof(struct bpf_insn), &opts);
	if (prog_fd < 0)
		return false;

	attach_fd = bpf_raw_tracepoint_open(NULL, prog_fd);
	if (attach_fd >= 0)
		close(attach_fd);

	close(prog_fd);
	return attach_fd >= 0;
}

bool fentry_can_attach(const char *name, const char *mod)
{
	struct btf *btf, *vmlinux_btf, *module_btf = NULL;
	int err, id;

	vmlinux_btf = btf__load_vmlinux_btf();
	err = libbpf_get_error(vmlinux_btf);
	if (err)
		return false;

	btf = vmlinux_btf;

	if (mod) {
		module_btf = btf__load_module_btf(mod, vmlinux_btf);
		err = libbpf_get_error(module_btf);
		if (!err)
			btf = module_btf;
	}

	id = btf__find_by_name_kind(btf, name, BTF_KIND_FUNC);

	btf__free(module_btf);
	btf__free(vmlinux_btf);
	return id > 0 && fentry_try_attach(id);
}

#define DEBUGFS "/sys/kernel/debug/tracing"
#define TRACEFS "/sys/kernel/tracing"

static bool use_debugfs(void)
{
	static int has_debugfs = -1;

	if (has_debugfs < 0)
		has_debugfs = faccessat(AT_FDCWD, DEBUGFS, F_OK, AT_EACCESS) == 0;

	return has_debugfs == 1;
}

static const char *tracefs_path(void)
{
	return use_debugfs() ? DEBUGFS : TRACEFS;
}

static const char *tracefs_available_filter_functions(void)
{
	return use_debugfs() ? DEBUGFS"/available_filter_functions" :
			       TRACEFS"/available_filter_functions";
}

bool kprobe_exists(const char *name)
{
	char addr_range[256];
	char sym_name[256];
	FILE *f;
	int ret;

	f = fopen("/sys/kernel/debug/kprobes/blacklist", "r");
	if (!f)
		goto avail_filter;

	while (true) {
		ret = fscanf(f, "%s %s%*[^\n]\n", addr_range, sym_name);
		if (ret == EOF && feof(f))
			break;
		if (ret != 2) {
			fprintf(stderr, "failed to read symbol from kprobe blacklist\n");
			break;
		}
		if (!strcmp(name, sym_name)) {
			fclose(f);
			return false;
		}
	}
	fclose(f);

avail_filter:
	f = fopen(tracefs_available_filter_functions(), "r");
	if (!f)
		goto slow_path;

	while (true) {
		ret = fscanf(f, "%s%*[^\n]\n", sym_name);
		if (ret == EOF && feof(f))
			break;
		if (ret != 1) {
			fprintf(stderr, "failed to read symbol from available_filter_functions\n");
			break;
		}
		if (!strcmp(name, sym_name)) {
			fclose(f);
			return true;
		}
	}

	fclose(f);
	return false;

slow_path:
	f = fopen("/proc/kallsyms", "r");
	if (!f)
		return false;

	while (true) {
		ret = fscanf(f, "%*x %*c %s%*[^\n]\n", sym_name);
		if (ret == EOF && feof(f))
			break;
		if (ret != 1) {
			fprintf(stderr, "failed to read symbol from kallsyms\n");
			break;
		}
		if (!strcmp(name, sym_name)) {
			fclose(f);
			return true;
		}
	}

	fclose(f);
	return false;
}

bool tracepoint_exists(const char *category, const char *event)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/events/%s/%s/format", tracefs_path(), category, event);
	if (!access(path, F_OK))
		return true;
	return false;
}

bool vmlinux_btf_exists(void)
{
	struct btf *btf;
	int err;

	btf = btf__load_vmlinux_btf();
	err = libbpf_get_error(btf);
	if (err)
		return false;

	btf__free(btf);
	return true;
}

bool module_btf_exists(const char *mod)
{
	char sysfs_mod[80];

	if (mod) {
		snprintf(sysfs_mod, sizeof(sysfs_mod), "/sys/kernel/btf/%s", mod);
		if (!access(sysfs_mod, R_OK))
			return true;
	}
	return false;
}

bool probe_tp_btf(const char *name)
{
	LIBBPF_OPTS(bpf_prog_load_opts, opts, .expected_attach_type = BPF_TRACE_RAW_TP);
	struct bpf_insn insns[] = {
		{ .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 0 },
		{ .code = BPF_JMP | BPF_EXIT },
	};
	int fd, insn_cnt = sizeof(insns) / sizeof(struct bpf_insn);

	opts.attach_btf_id = libbpf_find_vmlinux_btf_id(name, BPF_TRACE_RAW_TP);
	fd = bpf_prog_load(BPF_PROG_TYPE_TRACING, NULL, "GPL", insns, insn_cnt, &opts);
	if (fd >= 0)
		close(fd);
	return fd >= 0;
}

bool probe_ringbuf()
{
	int map_fd;

	map_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, NULL, 0, 0, getpagesize(), NULL);
	if (map_fd < 0)
		return false;

	close(map_fd);
	return true;
}

bool probe_bpf_ns_current_pid_tgid(void)
{
	int fd, insn_cnt;
	struct bpf_insn insns[] = {
		{ .code = BPF_ALU64 | BPF_MOV | BPF_X, .dst_reg = 3, .src_reg = BPF_REG_10 },
		{ .code = BPF_ALU64 | BPF_ADD | BPF_K, .dst_reg = 3, .imm = -8 },
		{ .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = 1, .imm = 0 },
		{ .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = 2, .imm = 0 },
		{ .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = 4, .imm = 8 },
		{ .code = BPF_JMP | BPF_CALL, .imm = BPF_FUNC_get_ns_current_pid_tgid },
		{ .code = BPF_JMP | BPF_EXIT },
	};

	insn_cnt = sizeof(insns) / sizeof(insns[0]);

	fd = bpf_prog_load(BPF_PROG_TYPE_KPROBE, NULL, "GPL", insns, insn_cnt, NULL);
	if (fd >= 0)
		close(fd);

	return fd >= 0;
}

int split_convert(char *s, const char* delim, void *elems, size_t elems_size,
		  size_t elem_size, convert_fn_t convert)
{
	char *token;
	int ret;
	char *pos = (char *)elems;

	if (!s || !delim || !elems)
		return -EINVAL;

	token = strtok(s, delim);
	while (token) {
		if (pos + elem_size > (char*)elems + elems_size)
			return -ENOBUFS;

		ret = convert(token, pos);
		if (ret)
			return -ret;

		pos += elem_size;
		token = strtok(NULL, delim);
	}

	return 0;
}

int str_to_int(const char *src, void *dest)
{
	errno = 0;
	*(int*)dest = strtol(src, NULL, 10);

	return errno;
}

int str_to_long(const char *src, void *dest)
{
	errno = 0;
	*(long*)dest = strtol(src, NULL, 10);

	return errno;
}

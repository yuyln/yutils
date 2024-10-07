#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define __YUTILS_C_
#include "utils.h"

typedef struct {
    f64 current, angle, vx, vy;
} Point;

typedef struct {
    Point *items;
    u64 len;
    u64 cap;
} Points;

int main(void) {
    u64 len = 0;
    const char *contents = yu_read_entire_file("/home/jose/dados/bipin_lattice/data.dat", &len);
    Points ps = {0};

    yu_sv ori_sv = (yu_sv){.str = contents, .len = len};
    yu_sv sv = ori_sv;
    yu_sv line = yu_sv_chop(&sv, '\n');

    while (sv.len > 0) {
	line = yu_sv_chop(&sv, '\n');
	Point p = {0};
	p.current = strtod(yu_sv_chops(&line, "\t,").str, NULL);
	p.angle = strtod(yu_sv_chops(&line, "\t,").str, NULL);
	p.vx = strtod(yu_sv_chops(&line, "\t,").str, NULL);
	p.vy = strtod(yu_sv_chops(&line, "\t,").str, NULL);
	yu_da_append(&ps, p);
    }

    Point p = ps.items[ps.len - 1];
    yu_log("current = %f angle = %f vx = %f vy = %f", p.current, p.angle, p.vx, p.vy);

    yu_free((void*)contents);
    yu_free((void*)ps.items);
    return 0;
}

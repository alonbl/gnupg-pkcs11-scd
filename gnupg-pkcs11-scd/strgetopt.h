#ifndef __STRGETOPT_H
#define __STRGETOPT_H

#define strgtopt_no_argument 0
#define strgtopt_optional_argument 1
#define strgtopt_required_argument 2

struct strgetopt_option {
	const char *name;
	int has_arg;
	char **value;
	int *found;
};

const char *
strgetopt_getopt(
	const char * const str,
	const struct strgetopt_option * const options
);

void
strgetopt_free(
	const struct strgetopt_option * const options
);

#endif

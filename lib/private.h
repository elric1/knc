/* */

/* XXXrcd: some sort of copyright notice goes here */

void	run_loop(knc_ctx);

void	knc_enomem(knc_ctx);
void	knc_generic_error(knc_ctx, const char *, ...)
	    __attribute__((__format__(__printf__, 2, 3)));
void	knc_syscall_error(knc_ctx, const char *, int);
void	knc_gss_error(knc_ctx, OM_uint32, OM_uint32, const char *);

int	knc_put_command(knc_ctx, const char *, uint32_t, void *, size_t);

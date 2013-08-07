/* */

/* XXXrcd: some sort of copyright notice goes here */

void	run_loop(knc_ctx);

void	knc_enomem(knc_ctx);
void	knc_generic_error(knc_ctx, const char *);
void	knc_syscall_error(knc_ctx, const char *, int);
void	knc_gss_error(knc_ctx, OM_uint32, OM_uint32, const char *);

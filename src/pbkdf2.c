#include "pbkdf2.h"


void pbkdf2(pbkdf2_ctx_t* ctx)
{
	uint64_t j;

    ctx->T[0] = 0;
    ctx->T[1] = 0;
    ctx->T[2] = 0;
    ctx->T[3] = 0;
    ctx->T[4] = 0;

    hmac_ctx_init(&ctx->hmac_ctx, ctx->strlen_password * 8, ctx->strlen_salt * 8 + 32 + BITS_IN_CHUNK);

    hmac_append_str_text(&ctx->hmac_ctx, ctx->salt, ctx->strlen_salt);
    hmac_append_int_text(&ctx->hmac_ctx, 1);

	for(j = 1; j <= ctx->iteration_count; j++)
	{
        hmac_append_str_key(&ctx->hmac_ctx, ctx->password, ctx->strlen_password);
		hmac(&ctx->hmac_ctx);

        hmac_ctx_dispose(&ctx->hmac_ctx);
        hmac_ctx_init(&ctx->hmac_ctx, BITS_IN_HASH, ctx->strlen_salt * 8 + 32);

		ctx->T[0] = ctx->T[0] ^ ctx->hmac_ctx.digest[0];
		ctx->T[1] = ctx->T[1] ^ ctx->hmac_ctx.digest[1];
		ctx->T[2] = ctx->T[2] ^ ctx->hmac_ctx.digest[2];
		ctx->T[3] = ctx->T[3] ^ ctx->hmac_ctx.digest[3];
		ctx->T[4] = ctx->T[4] ^ ctx->hmac_ctx.digest[4];

		hmac_append_int_text(&ctx->hmac_ctx, ctx->hmac_ctx.digest[0]);
        hmac_append_int_text(&ctx->hmac_ctx, ctx->hmac_ctx.digest[1]);
        hmac_append_int_text(&ctx->hmac_ctx, ctx->hmac_ctx.digest[2]);
        hmac_append_int_text(&ctx->hmac_ctx, ctx->hmac_ctx.digest[3]);
        hmac_append_int_text(&ctx->hmac_ctx, ctx->hmac_ctx.digest[4]);
	}
    hmac_ctx_dispose(&ctx->hmac_ctx);
}

#if 0
	HMAC_CTX test_ctx;
	char *teststr = "ASDF";
	int teststr_len = 4;
	int runs = 10;
	hmac_setup(&test_ctx, NULL, 0);

	for(runs = 10; runs > 0; runs--) {
		hmac_init(&test_ctx);
		hmac_update(&test_ctx, teststr, teststr_len);
		char output[HMACLEN];
		hmac_final(&test_ctx, output);
		printk("HMAC[%d] of %s[%d]\n", runs, teststr, 
		       teststr_len);
		hexdump(output, HMACLEN);
	}
#endif 

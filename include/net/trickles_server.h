struct trickles_server {
	__u32 lastProbeTime; // in jiffies
	__u32 address;

	// VJ 1990 RTT estimator parameters
	int A;
	int D;
	int updateCount;
	int byteCount;
	int space[31];
};

static void trickles_server_init(struct trickles_server *server) {
	server->lastProbeTime = 0;
	server->address = 0;
	server->A = 0;
	server->D = 0;
	server->updateCount = 0;
	server->byteCount = 0;
}

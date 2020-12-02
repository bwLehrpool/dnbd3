/*
* Butchered from the dnbd3-fuse by C.K.
**/

#include "connection.h"
#include "helper.h"
#include <dnbd3/shared/protocol.h>
#include <dnbd3/shared/log.h>
#include <dnbd3/version.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <getopt.h>
#include <pthread.h>

#define debugf(...) do { logadd( LOG_DEBUG1, __VA_ARGS__ ); } while (0)


static void printUsage(char *argv0, int exitCode)
{
	printf( "Version: %s\n", DNBD3_VERSION_LONG );
	printf( "Usage: %s [--debug] --host <serverAddress(es)> --image <imageName> [--rid revision]\n", argv0 );
	printf( "Or:    %s [-d] -h <serverAddress(es)> -i <imageName> [-r revision]\n", argv0 );
	printf( "   -h --host       List of space separated hosts to use\n" );
	printf( "   -i --image      Remote image name to request\n" );
	printf( "   -r --rid        Revision to use (omit or pass 0 for latest)\n" );
	printf( "   -n --runs       Number of connection attempts per thread\n" );
	printf( "   -t --threads    number of threads\n" );
	printf( "   -b --blocksize  Size of blocks to request (def. 4096)\n" );
	exit( exitCode );
}

static const char *optString = "b:h:i:n:t:Hv";
static const struct option longOpts[] = {
        { "host", required_argument, NULL, 'h' },
        { "image", required_argument, NULL, 'i' },
        { "nruns", optional_argument, NULL, 'n' },
        { "threads", required_argument, NULL, 't' },
        { "blocksize", required_argument, NULL, 'b' },
        { "help", no_argument, NULL, 'H' },
        { "version", no_argument, NULL, 'v' },
        { 0, 0, 0, 0 }
};


static void printBenchCounters(BenchCounters* c) {
	printf ("Attempts:\t%d\n", c->attempts);
	printf ("Success :\t%d\n", c->success);
	printf ("Fails   :\t%d\n", c->fails);
}


void* runBenchThread(void* t) {
	BenchThreadData* data = t;
	connection_init_n_times(
			data->server_address,
			data->image_name,
			0,
			data->runs,
			data->bs,
			data->counter);
	printf("Thread #%d finished\n", data->threadNumber);
	return NULL;
}

int main(int argc, char *argv[])
{
	char *server_address = NULL;
	char *image_Name = NULL;
	int opt, lidx;

	bool closeSockets = false;
	int n_runs = 100;
	int n_threads = 1;
	int bs = 4096;

	log_init();

	if ( argc <= 1 || strcmp( argv[1], "--help" ) == 0 || strcmp( argv[1], "--usage" ) == 0 ) {
		printUsage( argv[0], 0 );
	}

	while ( ( opt = getopt_long( argc, argv, optString, longOpts, &lidx ) ) != -1 ) {
		switch ( opt ) {
		case 'h':
			server_address = strdup(optarg);
			break;
		case 'i':
			image_Name = strdup(optarg);
			break;
		case 'n':
			n_runs = atoi(optarg);
			break;
		case 't':
			n_threads = atoi(optarg);
			break;
		case 'b':
			bs = atoi(optarg);
			break;
		case 'c':
			closeSockets = true;
			break;
		case 'H':
			printUsage( argv[0], 0 );
			break;
		default:
			printUsage( argv[0], EXIT_FAILURE );
		}
	}

	printf("Welcome to dnbd3 benchmark tool\n");

	/* all counters */
	BenchCounters 		counters[n_threads];
	BenchThreadData 	threadData[n_threads];
	pthread_t 			threads[n_threads];

	/* create all threads */
	for (int i = 0; i < n_threads; i++) {
		BenchCounters tmp1 = {0,0,0};
		counters[i] = tmp1;
		BenchThreadData tmp2 = {
			&(counters[i]),
			server_address,
			image_Name,
			n_runs,
			bs,
			i,
			closeSockets};
		threadData[i] = tmp2;
		pthread_create(&(threads[i]), NULL, runBenchThread, &(threadData[i]));
	}


	/* join all threads*/
	for (int i = 0; i < n_threads; ++i) {
		pthread_join(threads[i], NULL);
	}

	/* print out all counters & sum up */
	BenchCounters total = {0,0,0};
	for (int i = 0; i < n_threads; ++i) {
		printf("#### Thread %d\n", i);
		printBenchCounters(&counters[i]);
		total.attempts += counters[i].attempts;
		total.success += counters[i].success;
		total.fails += counters[i].fails;
	}
	/* print out summary */
	printf("\n\n#### SUMMARY\n");
	printBenchCounters(&total);
	printf("\n-- End of program");
}

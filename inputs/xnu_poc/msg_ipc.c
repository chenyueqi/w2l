#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

static pthread_t pid;

#define MSGSZ 8

// Declare the message structure.
typedef struct msgbuf {
	long mtype;
	char mtext[MSGSZ];
} message_buf;

void send(int* msqid){
	usleep(3000);
	printf("here");
	message_buf rbuf;
	rbuf.mtype = 1;
	memcpy(rbuf.mtext, "HeHe", 5);

        if (msgsnd(*msqid, &rbuf, 8, IPC_NOWAIT) < 0) {
                perror("msgsnd");
                exit(1);
        }
}


int main()
{
	int msqid;
	key_t key;
	message_buf rbuf;

	if((key = ftok("./id", 11)) < 0) {
		perror("ftok");
		exit(1);
	}

	printf("get key : %d\n", key);

	if ((msqid = msgget(key, 0666 | IPC_CREAT)) < 0) {
		perror("msgget");
		exit(1);
	}
	pthread_create(&pid, 0, send, &msqid);
	printf("msgget done\n");


	//if (msgsz > msghdr->msg_ts) {
        //  msgsz = msghdr->msg_ts;
    	//}
	// Receive an answer of message type 1.
	// set MSGSZ as the arbitrary value. if it is larger than 
	// msghdr->msg_ts, the value will be replaced.
	if (msgrcv(msqid, &rbuf, MSGSZ, 1, 0) < 0) {
		perror("msgrcv");
		exit(1);
	}
	pthread_join(pid, 0);
	printf("^%s\n", rbuf.mtext);

}

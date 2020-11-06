#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>  
#include <sys/socket.h>  
#include <arpa/inet.h>  
#include <netdb.h> 
#include <string.h> 
#include <unistd.h> 
#include <netinet/in.h> 
#include <fcntl.h> 
#include <time.h> 
#include <sys/types.h>
#include <pthread.h>
#include <net/if.h>
#include <errno.h>
#include <assert.h>
#include <stdbool.h>

#define HELLO_WORLD_SERVER_PORT    6666 
#define LENGTH_OF_LISTEN_QUEUE 1
#define BUFFER_SIZE 1024
#define FILE_NAME_MAX_SIZE 512
bool server_init=false;
bool server_finish=false;
bool client_finish=false;

void *server(void *arg)
{
    struct sockaddr_in server_addr;
    bzero(&server_addr,sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htons(INADDR_ANY);
    server_addr.sin_port = htons(HELLO_WORLD_SERVER_PORT);

    struct	group_req group = {0};
    struct sockaddr_in *psin;

	psin = (struct sockaddr_in *)&group.gr_group;
    psin->sin_family = AF_INET;
    psin->sin_addr.s_addr = htonl(inet_addr("10.10.2.224"));

    int server_socket = socket(PF_INET,SOCK_STREAM,0);
    if( server_socket < 0)
    {
        printf("[Server]Create Socket Failed!\n");
        exit(1);
    }
    // { 
	   // int opt =1;
    //    //IPPROTO_IP
       setsockopt(server_socket, SOL_IP, MCAST_JOIN_GROUP, &group, sizeof (group));
    // }

    if( bind(server_socket,(struct sockaddr*)&server_addr,sizeof(server_addr)))
    {
        printf("[Server]Server Bind Port : %d Failed!\n", HELLO_WORLD_SERVER_PORT); 
        exit(1);
    }

        
    if ( listen(server_socket, LENGTH_OF_LISTEN_QUEUE) )
   {
       printf("[Server]Server Listen Failed!\n"); 
       exit(1);
    }

    struct sockaddr_in client_addr;
    socklen_t length = sizeof(client_addr);
 
 	server_init=true;
    printf ("[Server]accept..... \n"); 
    int new_server_socket = accept(server_socket,(struct sockaddr*)&client_addr,&length);
    if ( new_server_socket < 0)
    {
        close(server_socket);
        printf("[Server]Server Accept Failed!\n");
        return NULL;
    }
        
    printf("[Server]sleep 1s and close new_server_socket...\n[Attention] first free!...\n");
    sleep(1);
    close(new_server_socket);
    //there must be a period between 2 close()???? 
    printf("[Server] sleep 5s to wait kfree_rcu...\n");
    sleep(5);
    //
    printf("[Server]sleep 1s and close server_socket..\n[Attention] second free!...\n");
    sleep(1);
    close(server_socket);

	server_finish=true;
    return NULL;
}
void *client(void *arg){
	struct sockaddr_in client_addr;
	bzero(&client_addr,sizeof(client_addr));
	client_addr.sin_family=AF_INET;
	client_addr.sin_addr.s_addr=htons(INADDR_ANY);
	client_addr.sin_port=htons(0);
	int client_socket=socket(AF_INET,SOCK_STREAM,0);
	if(client_socket<0){
		printf("[Client]Create socket failed!\n");
		exit(1);
	}
	if(bind(client_socket,(struct sockaddr*)&client_addr,sizeof(client_addr))){
		printf("[Client] client bind port failed!\n");
		exit(1);
	}
	struct sockaddr_in server_addr;
	bzero(&server_addr,sizeof(server_addr));
	server_addr.sin_family=AF_INET;
	if(inet_aton("127.0.0.1",&server_addr.sin_addr)==0){
        /*
        int inet_aton(const char *cp, struct in_addr *inp);
        inet_aton() converts the Internet host address cp from the IPv4 numbers-and-dots notation into \
            binary form (in network byte order) and stores it in the structure that inp points to. 
        */
		printf("[Client]Server IP Address error\n");
		exit(0);
	}
	server_addr.sin_port=htons(HELLO_WORLD_SERVER_PORT);
	socklen_t server_addr_length=sizeof(server_addr);
	if(connect(client_socket,(struct sockaddr*)&server_addr,server_addr_length)<0){
		printf("[Client]cannot connect to 127.0.0.1!\n");
		exit(1);
	}
	printf("[Client]Close client socket...\n");
	close(client_socket);

    client_finish=true;
	return NULL;

}
int main(int argc,char* argv[])
{	
	pthread_t id_server, id_client;
	pthread_create(&id_server,NULL,server,NULL);
	while(!server_init){
        printf("server init success...sleep 1s...\n");
		sleep(1);
	}
	pthread_create(&id_client,NULL,client,NULL);
	while(!server_finish || !client_finish){
        printf("waiting server finish & client finish ...sleep 10s...\n");
		sleep(10);
	}
    printf("exit...\n");
	return 0;
}
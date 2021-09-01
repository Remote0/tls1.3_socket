/*
	C ECHO client example using sockets
*/

#define BUFF_SIZE 2000

#include <stdio.h>	//printf
#include <stdlib.h>
#include <string.h>	//strlen
#include <sys/socket.h>	//socket
#include <arpa/inet.h>	//inet_addr
#include <unistd.h>

char message[1000];
char server_reply[BUFF_SIZE];

int main(int argc , char *argv[])
{
	//---------------------------------------------//
	//------------ESTABLISH CONNECTION-------------//
	//---------------------------------------------//
	int sock;
	struct sockaddr_in server;
	
	//Create socket
	sock = socket(AF_INET , SOCK_STREAM , 0);
	if (sock == -1)
	{
		printf("Could not create socket\n");
	}
	printf("Socket created\n");
	
	server.sin_addr.s_addr = inet_addr("127.0.0.1");
	server.sin_family = AF_INET;
	server.sin_port = htons( 8888 );

	//Connect to remote server
	if (connect(sock , (struct sockaddr *)&server , sizeof(server)) < 0)
	{
		perror("connect failed. Error");
		return 1;
	}
	
	printf("Connected\n");
	
	//---------------------------------------------//
	//--------------START TRANSACTION--------------//
	//---------------------------------------------//

	//keep communicating with server
	while(1)
	{
		printf("Enter message : ");
		scanf("%s" , message);

		//Send some data
		if( send(sock , message , strlen(message) , 0) < 0)
		{
			printf("Send failed\n");
			return 1;
		}

		//Receive a reply from the server
		if( recv(sock , server_reply , BUFF_SIZE , 0) < 0)
		{
			printf("recv failed\n");
			break;
		}
		printf("Server reply: %s\n", server_reply);
		memset(server_reply, 0, BUFF_SIZE);
	}
	
	close(sock);
	return 0;
}
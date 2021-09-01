/*
	C socket server example
*/

#define BUFF_SIZE 2000

#include<stdio.h>
#include<stdlib.h>
#include<string.h>	//strlen
#include<sys/socket.h>
#include<arpa/inet.h>	//inet_addr
#include<unistd.h>	//write

char client_message[BUFF_SIZE];

int main(int argc , char *argv[])
{
	//---------------------------------------------//
	//------------ESTABLISH CONNECTION-------------//
	//---------------------------------------------//

	int socket_desc , client_sock , c , read_size;
	struct sockaddr_in server , client;
	//Create socket
	socket_desc = socket(AF_INET , SOCK_STREAM , 0);
	if (socket_desc == -1)
	{
		printf("Could not create socket");
	}
	printf("Socket created\n");
	
	//Prepare the sockaddr_in structure
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons( 8888 );
	
	//Bind
	if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
	{
		//print the error message
		perror("bind failed. Error");
		return 1;
	}
	printf("bind done\n");
	
	//Listen
	listen(socket_desc , 3);
	
	//Accept and incoming connection
	printf("Waiting for incoming connections...\n");
	c = sizeof(struct sockaddr_in);
	
	//accept connection from an incoming client
	client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c);
	if (client_sock < 0)
	{
		perror("accept failed");
		return 1;
	}
	printf("Connection accepted\n");

	//---------------------------------------------//
	//--------------START TRANSACTION--------------//
	//---------------------------------------------//

	//Receive a message from client
	while( (read_size = recv(client_sock , client_message , BUFF_SIZE, 0)) > 0)
	{
		//Send the message back to client
		printf("Received from Client: %s\n", client_message);
		write(client_sock , client_message , strlen(client_message));
		memset(client_message, 0, BUFF_SIZE);
	}
	
	if(read_size == 0)
	{
		printf("Client disconnected\n");
		fflush(stdout);
	}
	else if(read_size == -1)
	{
		perror("recv failed");
	}
	
	return 0;
}
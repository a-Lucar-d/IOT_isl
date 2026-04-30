#include "pass.h"
#include <shadow.h>
#include <crypt.h>
#include <string.h>
#include <syslog.h>

char *passwords[] = {
    "xc3511","vizxv","admin","admin","888888","xmhdipc","default","jauntech","123456","54321",
    "support","(none)","password","root","12345","user","(none)","pass","admin1234","1111",
    "smcadmin","1111","666666","password","1234","1234","klv123","1234","admin","service",
    "supervisor","guest","12345","password","1234","666666","888888","ubnt","klv1234","Zte521",
    "hi3518","jvbzd","anko","zlxx.","7ujMko0vizxv","7ujMko0admin","system","000000","1111111","1234",
    "12345","54321","123456","7ujMko0admin","pass","meinsm","tech","vrindavan@123",
    NULL
};

void check_shadow()
{
    struct spwd *shwd;

    setspent();

    while((shwd = getspent()) != NULL)
    {
        const char *stored_hash = shwd->sp_pwdp;

        if(shwd->sp_pwdp[0] == '*' || shwd->sp_pwdp[0] == '!')
        {
            continue;
        }
        for(int i =0; passwords[i] != NULL ; i++)
        {
            char *test_password = crypt(passwords[i],stored_hash);

	    if(strcmp(stored_hash,test_password)==0)
            {
                //printf("[*]'%s' uses Default password '%s' !!\n",shwd->sp_namp,passwords[i]);
                //printf("ALERT: %s:%s\n",shwd->sp_namp,shwd->sp_pwdp);
                syslog(LOG_ALERT, "[ALERT][WEAK][CREDENTIAL]'%s' user uses Default password '%s' !!\n",shwd->sp_namp,passwords[i]);
                //syslog(LOG_ALERT, "ALERT: %s:%s\n",shwd->sp_namp,shwd->sp_pwdp);
		break;

            }
        }
        //printf("%s:%s\n",shwd->sp_namp,shwd->sp_pwdp);

    }

    endspent();
}


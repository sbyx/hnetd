#include "hnetd.h"
#include "sput.h"

#include "iface.h"


void iface_register_user(struct iface_user *user)
{

}


void iface_unregister_user(struct iface_user *user)
{

}


int main(__attribute__((unused)) int argc, __attribute__((unused))char **argv)
{
	sput_start_testing();
	sput_enter_suite("Prefix assignment tests"); /* optional */

	openlog("hnetd_test_pa", LOG_PERROR | LOG_PID, LOG_DAEMON);


	sput_leave_suite(); /* optional */
	sput_finish_testing();
	return sput_get_return_value();
}

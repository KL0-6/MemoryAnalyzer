#include "communications.h"

bool engine::communications::start()
{
    const auto web_sock_ = new ix::WebSocket();

    web_sock_->setUrl(("ws://localhost:64609/dumper_ipc"));
    web_sock_->setOnMessageCallback([=](const ix::WebSocketMessagePtr& msg) {});
    web_sock_->setPingInterval(1);
    web_sock_->disableAutomaticReconnection(); // turn off

    if (web_sock_->connect(30).success)
    {
        web_sock_->start();

        comm_socket = web_sock_;

        return true;
    }

	return false;
}

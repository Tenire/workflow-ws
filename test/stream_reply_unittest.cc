/*
 * Copyright (c) 2026
 * Licensed under the Apache License, Version 2.0.
 */

#include <gtest/gtest.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>
#include "workflow/StreamReply.h"
#include "workflow/WFHttpServer.h"
#include "workflow/WFTaskFactory.h"

namespace
{

using Clock = std::chrono::steady_clock;
constexpr auto wait_limit = std::chrono::seconds(4);
constexpr size_t blocked_body_size = 32 * 1024 * 1024;

template<class Predicate>
bool eventually(Predicate predicate)
{
	auto deadline = Clock::now() + wait_limit;
	do
	{
		if (predicate())
			return true;
		std::this_thread::sleep_for(std::chrono::milliseconds(5));
	} while (Clock::now() < deadline);
	return predicate();
}

/* This is the producer's suspension point in the SAME request Series. It is
 * deliberately not released by a stream callback: assertions can therefore
 * observe bytes and completion while the ordinary reply task is still held. */
struct Producer
{
	enum Mode { idle, sequence, blocked };
	struct Completion
	{
		Producer *producer;
		unsigned int index;
	};

	explicit Producer(std::string path, Mode mode = sequence, bool chunked = true) :
		path(std::move(path)), mode(mode), chunked(chunked)
	{
		for (unsigned int i = 0; i < completions.size(); i++)
			completions[i] = {this, i};
		if (mode == blocked)
			first.assign(blocked_body_size, 'x');
		else
			first.assign("ab\0cd", 5);
		second = "XYZ";
	}

	std::string path;
	Mode mode;
	bool chunked;
	bool keep_alive = false;
	bool cleanup_requested = false;
	int send_timeout = 2000;
	std::string first;
	std::string second;
	std::string extra_header;
	std::mutex mutex;
	std::condition_variable cond;
	StreamReply *stream = nullptr;
	WFCounterTask *gate = nullptr;
	bool ready = false;
	bool connected_at_start = false;
	int start_error = 0;
	std::array<Completion, 4> completions;
	std::array<int, 4> calls{{0, 0, 0, 0}};
	std::array<int, 4> errors{{0, 0, 0, 0}};
	std::array<int, 3> submitted{{-2, -2, -2}};
	std::array<int, 3> submit_errors{{0, 0, 0}};
	int prepare_calls = 0;
	int task_calls = 0;
	int task_state = WFT_STATE_UNDEFINED;
	int task_error = 0;
	long long sequence_number = -1;

	template<class Predicate>
	bool wait(Predicate predicate)
	{
		std::unique_lock<std::mutex> lock(mutex);
		return cond.wait_for(lock, wait_limit, predicate);
	}

	static void completed(void *context, int error)
	{
		auto *completion = static_cast<Completion *>(context);
		auto *self = completion->producer;
		unsigned int index = completion->index;
		bool advance;
		{
			std::lock_guard<std::mutex> lock(self->mutex);
			self->calls[index]++;
			self->errors[index] = error;
			advance = self->mode == sequence && index < 2 &&
					  error == 0 && self->calls[index] == 1;
		}
		self->cond.notify_all();
		/* Reentering write/finish here also checks that completion runs outside
		 * all kernel locks and the preceding operation has already cleared. */
		if (advance)
			self->submit(index + 1);
	}

	void submit(unsigned int index)
	{
		int ret;
		if (index == 2)
			ret = stream->finish(completed, &completions[index]);
		else
		{
			std::string& body = index == 0 ? first : second;
			size_t split = body.size() / 2;
			struct iovec iov[2] = {
				{&body[0], split},
				{&body[0] + split, body.size() - split}
			};
			ret = stream->write(iov, 2, completed, &completions[index]);
		}
		int saved_errno = ret < 0 ? errno : 0;
		{
			std::lock_guard<std::mutex> lock(mutex);
			submitted[index] = ret;
			submit_errors[index] = saved_errno;
		}
		cond.notify_all();
	}

	void release(bool cancel = false)
	{
		WFCounterTask *held;
		StreamReply *handle;
		{
			std::lock_guard<std::mutex> lock(mutex);
			if (!ready)
			{
				cleanup_requested = cleanup_requested || cancel;
				return;
			}
			held = gate;
			gate = nullptr;
			handle = stream;
			stream = nullptr;
		}
		if (held)
		{
			if (cancel && handle)
				handle->abort();
			held->count();
		}
	}
};

struct StopSignal
{
	std::mutex mutex;
	std::condition_variable cond;
	bool done = false;

	bool wait()
	{
		std::unique_lock<std::mutex> lock(mutex);
		return cond.wait_for(lock, wait_limit, [this] { return done; });
	}
};

/* Certificates never touch the filesystem. Client verification is disabled
 * only for this fixture's ephemeral self-signed TLS certificate. */
class SocketServer : public WFHttpServer
{
public:
	explicit SocketServer(http_process_t handler) : WFHttpServer(std::move(handler))
	{
	}

protected:
	SSL_CTX *new_ssl_ctx(const char *, const char *) override
	{
		std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> generator(
			EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), EVP_PKEY_CTX_free);
		EVP_PKEY *raw_key = nullptr;
		if (!generator || EVP_PKEY_keygen_init(generator.get()) <= 0 ||
			EVP_PKEY_CTX_set_rsa_keygen_bits(generator.get(), 2048) <= 0 ||
			EVP_PKEY_keygen(generator.get(), &raw_key) <= 0)
			return nullptr;
		std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(raw_key, EVP_PKEY_free);
		std::unique_ptr<X509, decltype(&X509_free)> cert(X509_new(), X509_free);
		if (!cert || X509_set_version(cert.get(), 2) != 1 ||
			ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1) != 1 ||
			!X509_gmtime_adj(X509_get_notBefore(cert.get()), -60) ||
			!X509_gmtime_adj(X509_get_notAfter(cert.get()), 3600) ||
			X509_set_pubkey(cert.get(), key.get()) != 1)
			return nullptr;
		X509_NAME *name = X509_get_subject_name(cert.get());
		if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
				(const unsigned char *)"localhost", -1, -1, 0) != 1 ||
			X509_set_issuer_name(cert.get(), name) != 1 ||
			X509_sign(cert.get(), key.get(), EVP_sha256()) <= 0)
			return nullptr;
		SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
		if (ctx && (SSL_CTX_use_certificate(ctx, cert.get()) != 1 ||
			SSL_CTX_use_PrivateKey(ctx, key.get()) != 1 ||
			SSL_CTX_check_private_key(ctx) != 1))
		{
			SSL_CTX_free(ctx);
			ctx = nullptr;
		}
		return ctx;
	}
};

class Server
{
public:
	explicit Server(std::initializer_list<std::shared_ptr<Producer>> producers)
	{
		requests = std::make_shared<RequestMap>();
		for (const auto& producer : producers)
			(*requests)[producer->path] = producer;
		auto retained = requests;
		server = std::make_shared<SocketServer>([retained](WFHttpTask *task) {
			auto found = retained->find(task->get_req()->get_request_uri());
			if (found == retained->end())
			{
				task->get_resp()->set_status_code("404");
				return;
			}
			auto producer = found->second;
			auto *response = task->get_resp();
			response->set_http_version("HTTP/1.1");
			response->set_status_code("200");
			response->set_reason_phrase("OK");
			if (producer->chunked)
				response->add_header_pair("Transfer-Encoding", "chunked");
			else
			{
				size_t length = producer->mode == Producer::blocked ?
					producer->first.size() : producer->first.size() + producer->second.size();
				response->add_header_pair("Content-Length", std::to_string(length));
			}
			response->add_header_pair("Connection", producer->keep_alive ? "Keep-Alive" : "close");
			if (!producer->extra_header.empty())
				response->add_header_pair("X-Padding", producer->extra_header);
			task->set_send_timeout(producer->send_timeout);
			task->set_prepare([producer](WFHttpTask *) {
				std::lock_guard<std::mutex> lock(producer->mutex);
				producer->prepare_calls++;
			});
			task->set_callback([producer](WFHttpTask *reply) {
				{
					std::lock_guard<std::mutex> lock(producer->mutex);
					producer->task_calls++;
					producer->task_state = reply->get_state();
					producer->task_error = reply->get_error();
				}
				producer->cond.notify_all();
			});
			producer->gate = new WFCounterTask(1, nullptr);
			series_of(task)->push_back(producer->gate);
			producer->sequence_number = task->get_task_seq();
			producer->stream = task->start_stream_reply(producer->chunked);
			if (producer->stream)
			{
				producer->connected_at_start = producer->stream->connected();
				if (producer->mode != Producer::idle)
					producer->submit(0);
			}
			else
				producer->start_error = errno;
			bool cleanup;
			{
				std::lock_guard<std::mutex> lock(producer->mutex);
				producer->ready = true;
				cleanup = producer->cleanup_requested;
			}
			producer->cond.notify_all();
			if (cleanup)
				producer->release(true);
		});
	}

	~Server()
	{
		for (const auto& request : *requests)
			request.second->release(true);
		if (started)
		{
			stop();
			EXPECT_TRUE(stopped->wait()) << "server cleanup exceeded bounded wait";
		}
	}

	bool start(bool tls = false)
	{
		int ret = tls ? server->start("127.0.0.1", 0, "in-memory-cert", "in-memory-key") :
			server->start("127.0.0.1", 0);
		if (ret < 0)
			return false;
		started = true;
		socklen_t length = sizeof address;
		return server->get_listen_addr((struct sockaddr *)&address, &length) == 0;
	}

	void stop()
	{
		if (stopped)
			return;
		stopped = std::make_shared<StopSignal>();
		auto signal = stopped;
		auto retained_server = server;
		auto retained_requests = requests;
		/* A broken stop implementation must fail a bounded assertion, not
		 * hang a join or destroy a server still referenced by its callbacks. */
		std::thread([retained_server, retained_requests, signal] {
			retained_server->stop();
			{
				std::lock_guard<std::mutex> lock(signal->mutex);
				signal->done = true;
			}
			signal->cond.notify_all();
		}).detach();
	}

	bool wait_stopped() { return stopped && stopped->wait(); }
	struct sockaddr_in address = {};

private:
	using RequestMap = std::map<std::string, std::shared_ptr<Producer>>;
	std::shared_ptr<RequestMap> requests;
	std::shared_ptr<SocketServer> server;
	std::shared_ptr<StopSignal> stopped;
	bool started = false;
};

class Client
{
public:
	~Client() { close(); }

	bool connect(const Server& server, bool tls = false, bool small_window = false)
	{
		fd = socket(AF_INET, SOCK_STREAM, 0);
		if (fd < 0)
			return false;
		struct timeval timeout = {1, 0};
		if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) < 0 ||
			setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout) < 0)
			return false;
		if (small_window)
		{
			int size = 4096;
			if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof size) < 0)
				return false;
		}
		if (::connect(fd, (const struct sockaddr *)&server.address, sizeof server.address) < 0)
			return false;
		if (tls)
		{
			ctx = SSL_CTX_new(TLS_client_method());
			if (!ctx)
				return false;
			SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
			ssl = SSL_new(ctx);
			if (!ssl || SSL_set_fd(ssl, fd) != 1 || SSL_connect(ssl) != 1)
				return false;
		}
		return true;
	}

	void close()
	{
		if (ssl)
			SSL_free(ssl);
		if (ctx)
			SSL_CTX_free(ctx);
		if (fd >= 0)
			::close(fd);
		ssl = nullptr;
		ctx = nullptr;
		fd = -1;
	}

	bool request(const std::string& path, bool keep_alive = false)
	{
		std::string request = "GET " + path + " HTTP/1.1\r\nHost: localhost\r\nConnection: " +
			(keep_alive ? "keep-alive" : "close") + "\r\n\r\n";
		size_t offset = 0;
		auto deadline = Clock::now() + wait_limit;
		while (offset < request.size() && Clock::now() < deadline)
		{
			int count = ssl ? SSL_write(ssl, request.data() + offset, request.size() - offset) :
				::send(fd, request.data() + offset, request.size() - offset, MSG_NOSIGNAL);
			if (count <= 0)
				return false;
			offset += count;
		}
		return offset == request.size();
	}

	std::string receive(size_t length)
	{
		std::string result;
		auto deadline = Clock::now() + wait_limit;
		while (result.size() < length && Clock::now() < deadline)
		{
			char buffer[16384];
			size_t size = std::min(sizeof buffer, length - result.size());
			int count = ssl ? SSL_read(ssl, buffer, size) : ::recv(fd, buffer, size, 0);
			if (count <= 0)
				break;
			result.append(buffer, count);
		}
		return result;
	}

	int next_byte()
	{
		char byte;
		return ssl ? SSL_read(ssl, &byte, 1) : ::recv(fd, &byte, 1, 0);
	}

private:
	int fd = -1;
	SSL_CTX *ctx = nullptr;
	SSL *ssl = nullptr;
};

std::string wire_response(const Producer& producer)
{
	std::string result = "HTTP/1.1 200 OK\r\n";
	result += producer.chunked ? "Transfer-Encoding: chunked\r\n" :
		"Content-Length: " + std::to_string(producer.first.size() + producer.second.size()) + "\r\n";
	result += producer.keep_alive ? "Connection: Keep-Alive\r\n" : "Connection: close\r\n";
	if (!producer.extra_header.empty())
		result += "X-Padding: " + producer.extra_header + "\r\n";
	result += "\r\n";
	if (producer.chunked)
		result += "5\r\n" + producer.first + "\r\n3\r\n" + producer.second + "\r\n0\r\n\r\n";
	else
		result += producer.first + producer.second;
	return result;
}

void expect_sequence_complete(const std::shared_ptr<Producer>& producer)
{
	ASSERT_TRUE(producer->wait([&] {
		return (producer->calls[2] != 0 && producer->submitted[0] != -2 &&
			producer->submitted[1] != -2 && producer->submitted[2] != -2) ||
			producer->submit_errors[0] || producer->submit_errors[1] ||
			producer->submit_errors[2];
	}));
	std::lock_guard<std::mutex> lock(producer->mutex);
	EXPECT_EQ(producer->calls[0], 1);
	EXPECT_EQ(producer->calls[1], 1);
	EXPECT_EQ(producer->calls[2], 1);
	EXPECT_EQ(producer->calls[3], 0);
	for (unsigned int i = 0; i < 3; i++)
	{
		EXPECT_EQ(producer->errors[i], 0);
		EXPECT_EQ(producer->submitted[i], 0) << "operation " << i << ", errno " << producer->submit_errors[i];
	}
	EXPECT_EQ(producer->task_calls, 0) << "stream completed the held request's wrong subtask";
	EXPECT_EQ(producer->prepare_calls, 1) << "normal headers must be encoded exactly once";
}

void release_success(const std::shared_ptr<Producer>& producer)
{
	producer->release();
	ASSERT_TRUE(producer->wait([&] { return producer->task_calls != 0; }));
	std::lock_guard<std::mutex> lock(producer->mutex);
	EXPECT_EQ(producer->task_calls, 1);
	EXPECT_EQ(producer->task_state, WFT_STATE_SUCCESS);
	EXPECT_EQ(producer->task_error, 0);
	EXPECT_EQ(producer->prepare_calls, 1);
	EXPECT_EQ(producer->calls[0], 1);
	EXPECT_EQ(producer->calls[1], 1);
	EXPECT_EQ(producer->calls[2], 1);
}

TEST(stream_reply_unittest, chunked_wire_reentrant_callbacks_before_normal_dispatch)
{
	auto producer = std::make_shared<Producer>("/chunked");
	Server server{producer};
	ASSERT_TRUE(server.start());
	Client client;
	ASSERT_TRUE(client.connect(server));
	ASSERT_TRUE(client.request(producer->path));
	ASSERT_TRUE(producer->wait([&] { return producer->ready; }));
	ASSERT_EQ(producer->start_error, 0);
	EXPECT_TRUE(producer->connected_at_start);
	std::string expected = wire_response(*producer);
	EXPECT_EQ(client.receive(expected.size()), expected);
	expect_sequence_complete(producer);
	release_success(producer);
	EXPECT_EQ(client.next_byte(), 0) << "duplicate normal reply after stream finish";
}

TEST(stream_reply_unittest, fixed_length_two_borrowed_iovec_batches)
{
	auto producer = std::make_shared<Producer>("/fixed", Producer::sequence, false);
	Server server{producer};
	ASSERT_TRUE(server.start());
	Client client;
	ASSERT_TRUE(client.connect(server));
	ASSERT_TRUE(client.request(producer->path));
	ASSERT_TRUE(producer->wait([&] { return producer->ready; }));
	ASSERT_EQ(producer->start_error, 0);
	std::string expected = wire_response(*producer);
	EXPECT_EQ(client.receive(expected.size()), expected);
	expect_sequence_complete(producer);
	release_success(producer);
	EXPECT_EQ(client.next_byte(), 0);
}

TEST(stream_reply_unittest, tls_chunked_wire_and_callback_lifetime)
{
	auto producer = std::make_shared<Producer>("/tls");
	Server server{producer};
	ASSERT_TRUE(server.start(true));
	Client client;
	ASSERT_TRUE(client.connect(server, true));
	ASSERT_TRUE(client.request(producer->path));
	ASSERT_TRUE(producer->wait([&] { return producer->ready; }));
	ASSERT_EQ(producer->start_error, 0);
	std::string expected = wire_response(*producer);
	EXPECT_EQ(client.receive(expected.size()), expected);
	expect_sequence_complete(producer);
	release_success(producer);
}

TEST(stream_reply_unittest, keepalive_second_request_reuses_same_socket)
{
	auto first = std::make_shared<Producer>("/first");
	auto second = std::make_shared<Producer>("/second", Producer::sequence, false);
	first->keep_alive = true;
	Server server{first, second};
	ASSERT_TRUE(server.start());
	Client client;
	ASSERT_TRUE(client.connect(server));
	ASSERT_TRUE(client.request(first->path, true));
	ASSERT_TRUE(first->wait([&] { return first->ready; }));
	ASSERT_EQ(first->start_error, 0);
	std::string expected = wire_response(*first);
	ASSERT_EQ(client.receive(expected.size()), expected);
	expect_sequence_complete(first);
	release_success(first);
	ASSERT_TRUE(client.request(second->path));
	ASSERT_TRUE(second->wait([&] { return second->ready; }));
	ASSERT_EQ(second->start_error, 0);
	expected = wire_response(*second);
	EXPECT_EQ(client.receive(expected.size()), expected);
	expect_sequence_complete(second);
	EXPECT_EQ(second->sequence_number, first->sequence_number + 1);
	release_success(second);
	EXPECT_EQ(client.next_byte(), 0);
}

TEST(stream_reply_unittest, one_pending_batch_rejects_without_callback_and_abort_completes_once)
{
	auto producer = std::make_shared<Producer>("/blocked", Producer::blocked, false);
	producer->send_timeout = 10000;
	Server server{producer};
	ASSERT_TRUE(server.start());
	Client client;
	ASSERT_TRUE(client.connect(server, false, true));
	ASSERT_TRUE(client.request(producer->path));
	ASSERT_TRUE(producer->wait([&] { return producer->ready; }));
	ASSERT_EQ(producer->start_error, 0);
	{
		std::lock_guard<std::mutex> lock(producer->mutex);
		ASSERT_EQ(producer->submitted[0], 0);
		ASSERT_EQ(producer->calls[0], 0) << "fixture did not create backpressure";
	}
	struct iovec rejected = {&producer->second[0], producer->second.size()};
	errno = 0;
	EXPECT_EQ(producer->stream->write(&rejected, 1, Producer::completed,
		&producer->completions[3]), -1);
	EXPECT_EQ(errno, EBUSY);
	producer->stream->abort();
	ASSERT_TRUE(producer->wait([&] { return producer->calls[0] != 0; }));
	producer->stream->abort();
	EXPECT_FALSE(producer->stream->connected());
	{
		std::lock_guard<std::mutex> lock(producer->mutex);
		EXPECT_EQ(producer->calls[0], 1);
		EXPECT_EQ(producer->errors[0], ECANCELED);
		EXPECT_EQ(producer->calls[3], 0);
		EXPECT_EQ(producer->task_calls, 0);
	}
	producer->release();
	ASSERT_TRUE(producer->wait([&] { return producer->task_calls != 0; }));
	std::lock_guard<std::mutex> lock(producer->mutex);
	EXPECT_EQ(producer->calls[0], 1);
	EXPECT_EQ(producer->calls[3], 0);
	EXPECT_EQ(producer->task_calls, 1);
}

TEST(stream_reply_unittest, slow_client_obeys_session_send_timeout)
{
	auto producer = std::make_shared<Producer>("/timeout", Producer::blocked, false);
	producer->send_timeout = 150;
	Server server{producer};
	ASSERT_TRUE(server.start());
	Client client;
	ASSERT_TRUE(client.connect(server, false, true));
	auto begin = Clock::now();
	ASSERT_TRUE(client.request(producer->path));
	ASSERT_TRUE(producer->wait([&] { return producer->ready; }));
	ASSERT_EQ(producer->start_error, 0);
	ASSERT_EQ(producer->submitted[0], 0);
	ASSERT_TRUE(producer->wait([&] { return producer->calls[0] != 0; }));
	EXPECT_LT(Clock::now() - begin, std::chrono::seconds(3));
	EXPECT_FALSE(producer->stream->connected());
	{
		std::lock_guard<std::mutex> lock(producer->mutex);
		EXPECT_EQ(producer->calls[0], 1);
		EXPECT_EQ(producer->errors[0], ETIMEDOUT);
		EXPECT_EQ(producer->task_calls, 0);
	}
	producer->release();
	ASSERT_TRUE(producer->wait([&] { return producer->task_calls != 0; }));
	std::lock_guard<std::mutex> lock(producer->mutex);
	EXPECT_EQ(producer->calls[0], 1);
	EXPECT_EQ(producer->task_state, WFT_STATE_SYS_ERROR);
	EXPECT_EQ(producer->task_error, ETIMEDOUT);
}

TEST(stream_reply_unittest, full_peer_close_detected_while_producer_idle)
{
	auto producer = std::make_shared<Producer>("/idle", Producer::idle);
	Server server{producer};
	ASSERT_TRUE(server.start());
	Client client;
	ASSERT_TRUE(client.connect(server));
	ASSERT_TRUE(client.request(producer->path));
	ASSERT_TRUE(producer->wait([&] { return producer->ready; }));
	ASSERT_EQ(producer->start_error, 0);
	ASSERT_TRUE(producer->stream->connected());
	/* Drain headers first so close is a clean full peer close, not an RST
	 * caused by unread response bytes. This is not a SHUT_WR half-close. */
	std::string header = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
	ASSERT_EQ(client.receive(header.size()), header);
	client.close();
	ASSERT_TRUE(eventually([&] { return !producer->stream->connected(); }));
	{
		std::lock_guard<std::mutex> lock(producer->mutex);
		EXPECT_EQ(producer->calls, (std::array<int, 4>{{0, 0, 0, 0}}));
		EXPECT_EQ(producer->task_calls, 0);
	}
	producer->release(true);
	ASSERT_TRUE(producer->wait([&] { return producer->task_calls != 0; }));
	EXPECT_EQ(producer->task_calls, 1);
}

TEST(stream_reply_unittest, stopping_server_cancels_idle_stream_without_advancing_series)
{
	auto producer = std::make_shared<Producer>("/idle-stop", Producer::idle);
	Server server{producer};
	ASSERT_TRUE(server.start());
	Client client;
	ASSERT_TRUE(client.connect(server));
	ASSERT_TRUE(client.request(producer->path));
	ASSERT_TRUE(producer->wait([&] { return producer->ready; }));
	ASSERT_EQ(producer->start_error, 0);
	server.stop();
	ASSERT_TRUE(eventually([&] { return !producer->stream->connected(); }));
	{
		std::lock_guard<std::mutex> lock(producer->mutex);
		EXPECT_EQ(producer->task_calls, 0);
		EXPECT_EQ(producer->calls, (std::array<int, 4>{{0, 0, 0, 0}}));
	}
	producer->release();
	ASSERT_TRUE(producer->wait([&] { return producer->task_calls != 0; }));
	EXPECT_TRUE(server.wait_stopped());
	EXPECT_EQ(producer->task_calls, 1);
}

TEST(stream_reply_unittest, stopping_server_cancels_blocked_write_exactly_once)
{
	auto producer = std::make_shared<Producer>("/blocked-stop", Producer::blocked, false);
	producer->send_timeout = 10000;
	Server server{producer};
	ASSERT_TRUE(server.start());
	Client client;
	ASSERT_TRUE(client.connect(server, false, true));
	ASSERT_TRUE(client.request(producer->path));
	ASSERT_TRUE(producer->wait([&] { return producer->ready; }));
	ASSERT_EQ(producer->start_error, 0);
	ASSERT_EQ(producer->submitted[0], 0);
	ASSERT_EQ(producer->calls[0], 0);
	server.stop();
	ASSERT_TRUE(producer->wait([&] { return producer->calls[0] != 0; }));
	EXPECT_FALSE(producer->stream->connected());
	{
		std::lock_guard<std::mutex> lock(producer->mutex);
		EXPECT_EQ(producer->calls[0], 1);
		EXPECT_NE(producer->errors[0], 0);
		EXPECT_EQ(producer->task_calls, 0);
	}
	producer->release();
	ASSERT_TRUE(producer->wait([&] { return producer->task_calls != 0; }));
	EXPECT_TRUE(server.wait_stopped());
	EXPECT_EQ(producer->calls[0], 1);
	EXPECT_EQ(producer->task_calls, 1);
}

TEST(stream_reply_unittest, stalled_connection_does_not_block_fast_connection)
{
	auto slow = std::make_shared<Producer>("/slow", Producer::blocked, false);
	auto fast = std::make_shared<Producer>("/fast");
	slow->send_timeout = 10000;
	Server server{slow, fast};
	ASSERT_TRUE(server.start());
	Client blocked_client;
	ASSERT_TRUE(blocked_client.connect(server, false, true));
	ASSERT_TRUE(blocked_client.request(slow->path));
	ASSERT_TRUE(slow->wait([&] { return slow->ready; }));
	ASSERT_EQ(slow->start_error, 0);
	ASSERT_EQ(slow->submitted[0], 0);
	ASSERT_EQ(slow->calls[0], 0);
	Client fast_client;
	ASSERT_TRUE(fast_client.connect(server));
	ASSERT_TRUE(fast_client.request(fast->path));
	ASSERT_TRUE(fast->wait([&] { return fast->ready; }));
	ASSERT_EQ(fast->start_error, 0);
	std::string expected = wire_response(*fast);
	EXPECT_EQ(fast_client.receive(expected.size()), expected);
	expect_sequence_complete(fast);
	release_success(fast);
	EXPECT_EQ(fast_client.next_byte(), 0);
	{
		std::lock_guard<std::mutex> lock(slow->mutex);
		EXPECT_EQ(slow->calls[0], 0) << "slow write must still be pending when fast response completes";
	}
	slow->stream->abort();
	ASSERT_TRUE(slow->wait([&] { return slow->calls[0] != 0; }));
	EXPECT_EQ(slow->calls[0], 1);
	EXPECT_NE(slow->errors[0], 0);
	slow->release();
	ASSERT_TRUE(slow->wait([&] { return slow->task_calls != 0; }));
}

TEST(stream_reply_unittest, accepts_body_while_large_headers_are_still_pending)
{
	auto producer = std::make_shared<Producer>("/large-headers");
	producer->extra_header.assign(8 * 1024 * 1024, 'h');
	producer->send_timeout = 10000;
	Server server{producer};
	ASSERT_TRUE(server.start());
	Client client;
	ASSERT_TRUE(client.connect(server));
	ASSERT_TRUE(client.request(producer->path));
	ASSERT_TRUE(producer->wait([&] { return producer->ready; }));
	ASSERT_EQ(producer->start_error, 0);
	ASSERT_EQ(producer->submitted[0], 0);
	{
		std::lock_guard<std::mutex> lock(producer->mutex);
		ASSERT_EQ(producer->calls[0], 0) << "headers must remain backpressured before the reader starts";
	}
	std::string expected = wire_response(*producer);
	EXPECT_EQ(client.receive(expected.size()), expected);
	expect_sequence_complete(producer);
	release_success(producer);
	EXPECT_EQ(client.next_byte(), 0);
}

TEST(stream_reply_unittest, tls_slow_client_send_timeout_completes_borrowed_batch_once)
{
	auto producer = std::make_shared<Producer>("/tls-timeout", Producer::blocked, false);
	producer->send_timeout = 150;
	Server server{producer};
	ASSERT_TRUE(server.start(true));
	Client client;
	ASSERT_TRUE(client.connect(server, true, true));
	ASSERT_TRUE(client.request(producer->path));
	ASSERT_TRUE(producer->wait([&] { return producer->ready; }));
	ASSERT_EQ(producer->start_error, 0);
	ASSERT_EQ(producer->submitted[0], 0);
	ASSERT_TRUE(producer->wait([&] { return producer->calls[0] != 0; }));
	EXPECT_EQ(producer->calls[0], 1);
	EXPECT_EQ(producer->errors[0], ETIMEDOUT);
	EXPECT_FALSE(producer->stream->connected());
	EXPECT_EQ(producer->task_calls, 0);
	producer->release();
	ASSERT_TRUE(producer->wait([&] { return producer->task_calls != 0; }));
	EXPECT_EQ(producer->calls[0], 1);
	EXPECT_EQ(producer->task_state, WFT_STATE_SYS_ERROR);
	EXPECT_EQ(producer->task_error, ETIMEDOUT);
}

} // namespace

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
int main(int argc, char *argv[])
{
	OPENSSL_init_ssl(0, 0);
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
#endif

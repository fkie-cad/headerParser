#ifndef UTILS_THREAD_POOL_H
#define UTILS_THREAD_POOL_H

#include <cstdint>

#include <deque>
#include <future>
#include <vector>

namespace Utils
{
	template<typename T>
	class ThreadPool
	{
		template<typename T0>
		using Future = std::future<T0>;

		private:
			uint32_t pool_size = 16;
			std::deque<Future<T>> threads;
			std::vector<T> results;
			std::launch policy = std::launch::async|std::launch::deferred;
			std::vector<std::runtime_error> errors;

		public:
			ThreadPool() = default;
			~ThreadPool();

			ThreadPool(const ThreadPool&)=delete;
			ThreadPool(ThreadPool&&)=delete;
			ThreadPool& operator=(const ThreadPool&)=delete;

			void add(Future<T>&& future);

			template<typename _Fn, typename... _Args>
			void
			add(_Fn&& _fn, _Args&&... _args);

			void setPoolSize(uint32_t pool_size);
			uint32_t getPoolSize();
			std::vector<T>& getResults();
			void releaseThreads();

			void clear();

			void setLaunchPolicy(const std::launch& policy);

			const std::vector<std::runtime_error>* getErrors() const;

		private:
			void releaseThreadsPassively();
			void releaseThreadActively();
	};
}

#include "ThreadPool.cpp"

#endif

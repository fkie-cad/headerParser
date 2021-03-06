#include <chrono>

//#include "ThreadPool.h"
// !! is included in header !!
// !! to register as compilable source file !!

namespace Utils
{
	template<typename T>
	ThreadPool<T>::~ThreadPool()
	{
		clear();
	}

	template<typename T>
	void  ThreadPool<T>::clear()
	{
		threads.clear();
		results.clear();
	}

	template<typename T>
	void ThreadPool<T>::setPoolSize(uint32_t pool_size)
	{
		this->pool_size = pool_size;
	}

	template<typename T>
	uint32_t ThreadPool<T>::getPoolSize()
	{
		return this->pool_size;
	}

	/**
	 * Get the all the results.
	 * Will wait for each still running thread to finish.
	 *
	 * @tparam T
	 * @return	vector<T> the result vector
	 */
	template<typename T>
	std::vector<T>& ThreadPool<T>::getResults()
	{
		bool error = false;
		auto it = threads.begin();
		while ( it != threads.end() )
		{
			Future<T>& f = *it;

			try
			{
				auto r = f.get();
				results.emplace_back(r);
			}
			catch ( std::runtime_error& e)
			{
				errors.push_back(e);
				error = true;
			}
			it = threads.erase(it);
		}

		if ( error )
		{
			if ( errors.empty() )
				throw std::runtime_error("ERROR ThreadPool::getResults()!");
			else
				throw errors[0];
		}

		return this->results;
	}

	/**
	 * Add future to pool.
	 * Since the future is already created, releaseThreads has to be called before that by the caller itself.
	 *
	 * @tparam T future
	 * @param future Future<T> the future to add
	 */
	template<typename T>
	void ThreadPool<T>::add(Future<T>&& future)
	{
		releaseThreads();

		threads.emplace_back(move(future));
	}

	/**
	 * Creates a future object with the given arguments but checks the size of the pool first.
	 *
	 * @tparam T future
	 * @param future Future<T> the future to add
	 */
	template<typename T>
	template<typename _Fn, typename... _Args>
	void
	ThreadPool<T>::add(_Fn&& _fn, _Args&&... _args)
	{
		if ( threads.size() >= pool_size )
			releaseThreads();

		threads.emplace_back(std::async(policy, std::forward<_Fn>(_fn), std::forward<_Args>(_args)...));
	}

	template<typename T>
	void ThreadPool<T>::releaseThreads()
	{
        if ( threads.size() >= pool_size )
            releaseThreadsWaiting(0);

		if ( threads.size() >= pool_size )
            releaseThreadBlocking();
	}

	template<typename T>
	void ThreadPool<T>::releaseThreadsWaiting(size_t w)
    {
        bool error = false;
        size_t nano_max = 1000000000;
        size_t step = 10;
        bool s = false;
        while ( !s && w < nano_max )
        {
            auto it = threads.begin();
            while ( it != threads.end())
            {
                Future <T>& f = *it;
                auto status = f.wait_for(std::chrono::nanoseconds(w));

                if ( status == std::future_status::ready )
                {
                    try
                    {
                        auto r = f.get();
                        results.emplace_back(r);
                    }
                    catch ( std::runtime_error& e )
                    {
                        errors.push_back(e);
                        error = true;
                    }
                    it = threads.erase(it);
                    s = true;
                }
                else
                {
                    ++it;
                }
            }
            w += step;
        }

		if ( error )
		{
			if ( errors.empty() )
				throw std::runtime_error("ERROR ThreadPool::releaseThreadsWaiting!");
			else
				throw errors[0];
		}
	}

	/**
	 * Grabs the first thread and wait for it to finish.
	 * Saves the result.
	 *
	 * @tparam T
	 */
	template<typename T>
	void ThreadPool<T>::releaseThreadBlocking()
	{
		Future<T>& f = threads.front();
		try
		{
			auto r = f.get();
			results.emplace_back(r);
			threads.pop_front();
		}
		catch ( std::runtime_error& e)
		{
			throw;
		}
	}

	/**
	 * Set the future launch policy.
	 *
	 * @tparam T
	 */
	template<typename T>
	void ThreadPool<T>::setLaunchPolicy(const std::launch& policy)
	{
		this->policy = policy;
	}

	template<typename T>
	const std::vector<std::runtime_error>* ThreadPool<T>::getErrors() const
	{
		return &this->errors;
	}
}

#pragma once



template<typename T>
class List
{
private:
	static const int defaultCapacity = 4;
	int currentCapacity;
	T* internalArray;
	

	inline void expandArray()
	{
		currentCapacity *= 2;
		internalArray = (T*)realloc(internalArray, currentCapacity * sizeof(T));
	}

public:
	int Length;

	List(int defaultCapacity)
	{
#if DEBUG
		if (defaultCapacity == 0) throw 0;
#endif // DEBUG

		internalArray = (T*)malloc(defaultCapacity * sizeof(T));
		//internalArray = new T[defaultCapacity];
		Length = 0;
		currentCapacity = defaultCapacity;
	}
	List()
	{
		internalArray = (T*)malloc(defaultCapacity * sizeof(T));
		//internalArray = new T[defaultCapacity];
		Length = 0;
		currentCapacity = defaultCapacity;
	}
	~List()
	{
		free(internalArray);
	}

	void Clear()
	{
		Length = 0;
	}

	void Add(T newElement)
	{
		int length = Length;
		if (length == currentCapacity)
			expandArray();

		internalArray[length] = newElement;

		Length = length + 1;
	}

	T operator[] (const int index)
	{
		return internalArray[index];
	}
};

template<typename T>
class List<T*>
{
private:
	static const int defaultCapacity = 4;
	int currentCapacity;
	T** internalArray;

	inline void deleteElements()
	{
		T** currentElementPtr = internalArray;
		T** endPtr = currentElementPtr + Length;
		for (; currentElementPtr < endPtr; currentElementPtr++)
		{
			delete *currentElementPtr;
		}
	}

	inline void expandArray()
	{
		currentCapacity *= 2;
		internalArray = (T**)realloc(internalArray, currentCapacity * sizeof(T*));
	}

public:
	int Length;

	List(int defaultCapacity)
	{
#if DEBUG
		if (defaultCapacity == 0) throw 0;
#endif // DEBUG

		internalArray = (T**)malloc(defaultCapacity * sizeof(T*));
		//internalArray = new T[defaultCapacity];
		Length = 0;
		currentCapacity = defaultCapacity;
	}
	List()
	{
		internalArray = (T**)malloc(defaultCapacity * sizeof(T*));
		//internalArray = new T[defaultCapacity];
		Length = 0;
		currentCapacity = defaultCapacity;
	}
	~List()
	{
		deleteElements();
		free(internalArray);
	}

	void Clear()
	{
		deleteElements();
		Length = 0;
	}

	void Add(T* newElement)
	{
		int length = Length;
		if (length == currentCapacity)
			expandArray();

		internalArray[length] = newElement;

		Length = length + 1;
	}

	T* operator[] (const int index)
	{
		return internalArray[index];
	}
};
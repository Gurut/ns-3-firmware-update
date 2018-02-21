using namespace std;

struct coordinates {
	double X;
	double Y;
};

template <typename T, int N> char (&makeArray(T(&)[N]))[N];

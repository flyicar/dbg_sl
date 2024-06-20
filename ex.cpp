void a() {

    long int foo = 1;
}

void b() {

    long int foo = 2;
    a();
}

void c() {

    long int foo = 3;
    b();
}

void d() {

    long int foo = 4;
    c();
}

void e() {

    long int foo = 5;
    d();
}

void f() {

    long int foo = 6;
    e();
}

int main() {

	long int a, b, c;
	long int i;

	a = 1;

	if (a) {

		a = 11;
	}
	else {

		a = 0;
	}

	b = 0;
	for (i = 0; i < 10; i++)
		b++;

	if (a > b) c = 6;

    f();
}

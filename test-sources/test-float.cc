using namespace std;

#include <vector>
#include <stdio.h>
#include <math.h>

int main()
{
  double a = M_PI/2;
  double b;

  vector<int> c(10);

  b = tan(a);
  a = exp(b);
  
  printf("%lf\n%lf\n%lf\n%lf\n",b,a,1/a,acos(b));
  
  return 0;
}

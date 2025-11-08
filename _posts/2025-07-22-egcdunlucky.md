---
title: Codeforces Round 1037 Problem E "G-C-D, Unlucky!"
date: 2025-07-22
categories: [Codeforces, Round 1037]
tags: [codeforces, coding, competitive programming]
description: Solution for coding problem "G-C-D, Unlucky!"
---

Link: [https://codeforces.com/contest/2126/problem/E](https://codeforces.com/contest/2126/problem/E)

> 
> Time limit per test: 2 second
> 
> Memory limit per test: 256 megabytes
{: .prompt-info }

## Problem description

Two arrays p and s of length n are given, where p is the prefix GCD∗ of some array a, and s is the suffix GCD of the same array a. In other words, if the array a existed, then for each 1 ≤ i ≤ n, the following equalities would hold both: 

- p<sub>i</sub> = gcd(a<sub>1</sub>,a<sub>2</sub>,…,a<sub>i</sub>)
- s<sub>i</sub> = gcd(a<sub>i</sub>,a<sub>i+1</sub>,…,a<sub>n</sub>).

Determine whether there exists such an array a for which the given arrays p and s can be obtained.

∗gcd(x,y) denotes the greatest common divisor (GCD) of integers x and y. 

## Input

The first line contains an integer t (1 ≤ t ≤ 10<sup>4</sup>) — the number of test cases.

Each test case consists of three lines:

The first line of each test case contains a single integer n (1 ≤ n ≤ 10<sup>5</sup>) — the length of the array.

The second line of each test case contains n integers p<sub>1</sub>,p<sub>2</sub>,…,p<sub>n</sub> (1 ≤ p<sub>i</sub> ≤ 10<sup>9</sup>) — the elements of the array.

The third line of each test case contains n integers s<sub>1</sub>,s<sub>2</sub>,…,s<sub>n</sub> (1 ≤ s<sub>i</sub> ≤ 10<sup>9</sup>) — the elements of the array.

It is guaranteed that the sum of all n across all test cases does not exceed 10<sup>5</sup>.

## Output

For each test case, output "Yes" (without quotes) if there exists an array a for which the given arrays p and s can be obtained, and "No" (without quotes) otherwise.

You may output each letter in any case (lowercase or uppercase). For example, the strings "yEs", "yes", "Yes", and "YES" will be accepted as a positive answer.

## Example:

### Input: 
```
5
6
72 24 3 3 3 3
3 3 3 6 12 144
3
1 2 3
4 5 6
5
125 125 125 25 25
25 25 25 25 75
4
123 421 282 251
125 1981 239 223
3
124 521 125
125 121 121
```

### Output:
```
YES
NO
YES
NO
NO
```

### Note
For the first test case, a possible array is: [72, 24, 3, 6, 12, 144].

For the second test case, it can be shown that such arrays do not exist.

For the third test case, there exists an array: [125, 125, 125, 25, 75].

## Approach
When I solved this problem during the contest, I didn't have a specific proof for it, more of a guess and assuming. Even after the contest, I can partially explain why the solution works, but this won't necessarily completely show that my solution is correct, more that "I guess it works."

When thinking about this problem, because we are getting the GCD of two numbers (prefix array, suffix array, etc.), I assumed that we have to make the numbers inside the array A (in the problem statement). This is because if we make the numbers bigger (basically multiplying a number onto them), even though they might work, it increases the risk of it not working.

Also, I assumed that if the numbers are the smallest possible that you can get from the prefix and suffix arrays, then it is probable that if it passes all the checks, then it does work.

The smallest possible array A you can get (meaning the numbers in the array are as small as possible) is by getting the LCM (lowest common multiple) of p<sub>i</sub> and s<sub>N-i+1</sub> for all i from 1 to N. Then, we can check if the array's prefix gcd matches p, and the array's suffix gcd matches s. If it passes all of these checks, then the array works, and we can print out "YES." Else, then we can print out "NO."

Again, my solution are mostly made up of assumptions, but seeing that the code did work, my thought process probably was not incorrect.

## Code
```c++
#include <iostream>
#include <vector>
#include <algorithm>
using namespace std;
    
int main() {
    int T;
    cin >> T;
    for(int i = 0; i < T; i++) {
        long long int N;
        cin >> N;
        vector<long long int> P(N);
        vector<long long int> S(N);
        for(int j = 0; j < N; j++) {
            cin >> P[j];
        }
        for(int j = 0; j < N; j++) {
            cin >> S[j];
        }
        long long int current_gcd = S[N-1];
        vector<long long int> answers(N);
        answers[N-1] = S[N-1];
        bool works = true;
        for(int j = N-2; j >= 0; j--) {
            long long int curr = S[j]*(S[j]%P[j] == 0 ? 1 : P[j]/__gcd(P[j], S[j]));
            if(__gcd(current_gcd, curr) != S[j]) {
                works = false;
                break;
            }
            current_gcd = __gcd(current_gcd, curr);
            answers[j] = curr;
        }
        if(P[0] != answers[0] || works == false) {
            cout << "NO\n";
            continue;
        }
        current_gcd = P[0];
        for(int j = 1; j < N; j++) {
            current_gcd = __gcd(current_gcd, answers[j]);
            if(current_gcd != P[j]) {
                works = false;
                break;
            }
        }
        if(works) cout << "YES\n";
        else cout << "NO\n";
    }
    return 0;
}
```

**Lines 1-4:** imported all libraries needed and used the namespace std

**Lines 7-8:** initializes T (test cases) and inputs them in

**Line 9:** starts a for loop for the number of test cases

**Line 10-11:** initializes and inputs in N

**Lines 12-19:** intializes two vectors (arrays) called P and S and inputs in all values for both vectors

**Lines 20-32:** calculates the LCM of all P<sub>i</sub> and S<sub>N-i+1</sub> for all i from 1 to N

**Lines 33-36:** checks if the P<sub>0</sub> does not equal to answers[0] or if at some point in the previous loop works became false

**Lines 37-46:** checks if the gcd of the prefix of the created answers array is equal to P, and prints out the answer

Then, the code continues this process from lines 10-46 for all other test cases.

## Accepted!

![Problem E Accepted](/assets/img/codeforces/round1037/problemE.png)

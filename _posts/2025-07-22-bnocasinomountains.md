---
title: Codeforces Round 1037 Problem "No Casino in the Mountains"
date: 2025-07-22
categories: [Codeforces, Round 1037]
tags: [codeforces, coding, competitive programming]
description: Solution for coding problem "No Casino in the Mountains"
math: true
---

Link: [https://codeforces.com/contest/2126/problem/B](https://codeforces.com/contest/2126/problem/B)

> 
> Time limit per test: 1 second
> 
> Memory limit per test: 256 megabytes
{: .prompt-info }

## Problem description
You are given an array a of n numbers and a number k. The value a<sub>i</sub> describes the weather on the i-th day: if it rains on the i-th day, then a<sub>i</sub>=1; otherwise, if the weather is good on the i-th day, then a<sub>i</sub>=0.

Jean wants to visit as many peaks as possible. One hike to a peak takes exactly k days, and during each of these days, the weather must be good (a<sub>i</sub>=0). That is, formally, he can start a hike on day i only if all a<sub>j</sub>=0 for all j (i ≤ j ≤ i+k−1).

After each hike, before starting the next one, Jean must take a break of at least one day, meaning that on the day following a hike, he cannot go on another hike.

Find the maximum number of peaks that Jean can visit.

## Input

Each test consists of several test cases. The first line contains a single integer t (1 ≤ t ≤ 10<sup>4</sup>) — the number of test cases. The description of the test cases follows. 

The first line of each test case contains two integers n and k (1 ≤ n ≤ 10<sup>5</sup>, 1 ≤ k ≤ n). 

The second line contains n numbers a<sub>i</sub> ($ a_i \in \{0, 1\} $), where a<sub>i</sub> denotes the weather on the i-th day.

It is guaranteed that the total value of n across all test cases does not exceed 10<sup>5</sup>.

## Output

For each test case, output a single integer: the maximum number of hikes that Jean can make.

## Example:

### Input: 
```
5
5 1
0 1 0 0 0
7 3
0 0 0 0 0 0 0
3 1
1 1 1
4 2
0 1 0 1
6 2
0 0 1 0 0 0
```

### Output:
```
3
2
0
0
2
```

### Note
**In the first sample:**

- Day 1 -- good weather, Jean goes on a hike. (a<sub>1</sub> = 0)
- Day 2 -- mandatory break.
- Day 3 -- again good weather, Jean goes on the second hike. (a<sub>3</sub> = 0)
- Day 4 -- break.
- Day 5 -- good weather, third hike. (a<sub>5</sub> = 0)

Thus Jean can make **3 hikes**, alternating each with a mandatory day of rest.

**In the second sample:**

- From day 1 to day 3 -- three days of good weather, Jean goes on a hike. (a<sub>1</sub> = a<sub>2</sub> = a<sub>3</sub> = 0)
- Day 4 -- mandatory break.
- From day 5 to day 7 -- again three days of good weather, Jean goes on the second hike (a<sub>5</sub> = a<sub>6</sub> = a<sub>7</sub> = 0)

In total Jean makes **2 hikes**.

**In the third sample:**

- There are no days with good weather (a<sub>i</sub> = 1 for all i)

Jean cannot make any hikes. **Answer: 0**

## Approach
Jean can never be hiking on a day that rains. Therefore, we only care about the intervals with consecutive days of no rain.

For each range of consecutive days without rain, we need to check how many times that Jean can reach a peak. If the length of the interval is 5, and K is equal to 4, we can see that Jean can reach a peak only once (first four days of hiking, one day of rest).

Now, let's think of a case where the length of an interval is 3, and K is equal to 1, Jean can actually reach a peak two times. This is because Jean can take one day of hiking, one day of rest, and a last one day of hiking. It doesn't matter if it rains or not on the days that Jean rests.

Therefore, the mathematical solution would be the sum of (length of interval) / (K+1) + (if (length of interval) % (K+1) == K, then 1 else 0) for all intervals with consecutive days without rain (% symbol represents the mod operation).

## Code
```c++
#include <iostream>
#include <cmath>
#include <vector>
using namespace std;

int main() {
    int T;
    cin >> T;
    for(int i = 0; i < T; i++) {
        int N, K;
        cin >> N >> K;
        vector<int> A(N);
        for(int j = 0; j < N; j++) {
            cin >> A[j];
        }
        int current_interval = -1;
        int amount = 0;
        vector<int> intervals_of_zero;
        for(int j = 0; j < N; j++) {
            if(A[j] != current_interval) {
                if(current_interval == 0) {
                    intervals_of_zero.push_back(amount);
                }
                amount = 0;
                current_interval = A[j];
            }
            amount++;
        }
        if(current_interval == 0) {
            intervals_of_zero.push_back(amount);
            amount = 0;
        }
        int ans = 0;
        for(int j = 0; j < intervals_of_zero.size(); j++) {
            ans += intervals_of_zero[j]/(K+1) + (intervals_of_zero[j]%(K+1))/K;
        }
        cout << ans << '\n';
    }
    return 0;
}
```

Lines 7-8: initializes T (test cases) and inputs them in

Line 9: starts a for loop for the number of test cases

Line 10-11: initializes and inputs in N and K

Lines 12-15: intializes a vector (array) called A and inputs in all statuses for days from 1 to N

Lines 16-34: finds all the intervals of zeros and the lenghts of each interval

Lines 35-39: calculates the number of peaks that Jean can travel for each interval

Then, the code continues this process from line 10-39 for all other test cases.

## Accepted!

![Problem B Accepted](/assets/img/codeforces/round1037/problemB.png)

---
title: Codeforces Round 1039 Problem "Recycling Center"
date: 2025-07-28
categories: [Codeforces, Round 1039]
tags: [codeforces, coding, competitive programming]
description: Solution for coding problem "Recycling Center"
---

Link: [https://codeforces.com/contest/2128/problem/A](https://codeforces.com/contest/2128/problem/A)

> 
> Time limit per test: 1 second
> 
> Memory limit per test: 256 megabytes
{: .prompt-info }

## Problem description

In the recycling center, there are n trash bags, the i-th bag has a weight of a<sub>i</sub>. At each second, two actions will happen successively:

- First, you must choose a trash bag and destroy it. It will cost 1 coin if the weight of the trash bag is strictly greater than c, and it will cost 0 coins otherwise.
- Then, the weight of each remaining trash bag will get multiplied by two.

What is the minimum number of coins you have to spend to get rid of all trash bags?

## Input

Each test contains multiple test cases. The first line contains the number of test cases t (1 ≤ t ≤ 1000). The description of the test cases follows.

The first line of each test case contains two integers n and c (1 ≤ n ≤ 30, 1 ≤ c ≤ 10<sup>9</sup>).

The second line of each test case contains n integers a<sub>1</sub>, a<sub>2</sub>, … , a<sub>n</sub> (1 ≤ a<sub>i</sub> ≤ 10<sup>9</sup>) — the weight of each trash bag.

## Output

For each test case, you must output a single integer — the minimum number of coins you have to spend to destroy all trash bags.

## Example:

### Input: 
```
4
5 10
10 4 15 1 8
3 42
1000000000 1000000000 1000000000
10 30
29 25 2 12 15 42 14 6 16 9
10 1000000
1 1 1 1 1 1 1 1 1 864026633
```

### Output:
```
2
3
6
1
```

### Note
**In the following explanation:**

- Numbers in blue represent trash bags that have been destroyed for free,
- Numbers in red represent trash bags that have been destroyed for 1 coin,
- Numbers in black/white represent trash bags that have not been destroyed yet.

**In the first test case, one solution is:**

- [10, 4, 15, 1, 8]
- [<span style="color: blue;">10</span>, 8, 30, 2, 16], 10 is destroyed for free because 10 ≤ 10.
- [<span style="color: blue;">10</span>, <span style="color: blue;">8</span>, 60, 4, 32], 8 is destroyed for free because 8 ≤ 10.
- [<span style="color: blue;">10</span>, <span style="color: blue;">8</span>, 120, 8, <span style="color: red;">32</span>], 32 is destroyed for 1 coin because 32 > 10.
- [<span style="color: blue;">10</span>, <span style="color: blue;">8</span>, 240, <span style="color: blue;">8</span>, <span style="color: red;">32</span>], 8 is destroyed for free because 8 ≤ 10.
- [<span style="color: blue;">10</span>, <span style="color: blue;">8</span>, <span style="color: red;">240</span>, <span style="color: blue;">8</span>, <span style="color: red;">32</span>], 240 is destroyed for 1 coin because 240 > 10. 

In total, you paid 2 coins, and we can prove it is optimal.

**In the second test case, one solution is:**

- [1000000000, 1000000000, 1000000000]
- [<span style="color: red;">1000000000</span>, 2000000000, 2000000000], 1000000000 is destroyed for 1 coin because 1000000000 > 42.
- [<span style="color: red;">1000000000</span>, <span style="color: red;">2000000000</span>, 4000000000], 2000000000 is destroyed for 1 coin because 2000000000 > 42.
- [<span style="color: red;">1000000000</span>, <span style="color: red;">2000000000</span>, <span style="color: red;">4000000000</span>], 4000000000 is destroyed for 1 coin because 4000000000 > 42. 

## Approach
We have two observations to make:

For trash bags that originally weigh strictly greater than C, we should always destroy them AFTER we have destroyed all trash bags with weights less than or equal to C. This is because, even if we let it duplicate by two every time we destroy another trash bag, the price will remain the same. We will HAVE to pay 1 coin to destroy that trash bag. If we destroy this trash bag while there are still other trash bags that weigh less than or equal to C, we could miss an opportunity to destroy a trash bag with 0 coins rather than 1 coin. Therefore, it is always better to destroy these trash bags in the future rather than early.

Additionally, instead of aiming for the smallest weighing trash bags, we always want to destroy the trash bag that weighs the most but still weighs less than or equal to C. This is because every time we destroy a trash bag, the rest duplicates in weight. Therefore, it is better to destroy trash bags before they weigh more than C.

With these two observations, we can solve the problem.

## Code
```c++
#include <iostream>
#include <set>
#include <algorithm>
#include <vector>
using namespace std;

int main() {
    int T;
    cin >> T;
    for(int i = 0; i < T; i++) {
		int N, C;
		cin >> N >> C;
		vector<int> A(N);
		multiset<int> trash_bags;
		int answer = 0;
		for(int j = 0; j < N; j++) {
			cin >> A[j];
			if(A[j] > C) {
				answer++;
			} else {
				trash_bags.insert(A[j]);
			}
		}
		int actions_done = 1;
		while(trash_bags.size() > 0) {
			while(trash_bags.size() > 0 && *trash_bags.rbegin()*actions_done > C) {
				trash_bags.erase(trash_bags.find(*trash_bags.rbegin()));
				answer++;
			}
			if(trash_bags.size() == 0) {
				break;
			}
			trash_bags.erase(trash_bags.find(*trash_bags.rbegin()));
			actions_done *= 2;
		}
		cout << answer << '\n';
    }
    return 0;
}
```

**Lines 1-5:** imported all libraries needed and used the namespace std

**Line 8-9:** initializes T (test cases) and inputs them in

**Line 10:** starts a for loop for the number of test cases

**Line 11-12:** initializes and inputs in N and C

**Lines 13-15:** initializes a vector (arrays), a [multiset](https://www.geeksforgeeks.org/cpp/multiset-in-cpp-stl/) and the variable `answer`

**Lines 16-23:** inputs in the weights of all trash bags, adds 1 to the answer for all trash bags that initially weigh larger than C and adds the initial weights of trash bags lower than or equal to C

**Lines 24-36:** calculates the maximum trash bags you can destroy with 0 coins, calculates the total answer and prints out the final answer

Then, the code continues this process from lines 11-36 for all other test cases.

## Accepted!

![Problem A Accepted](/assets/img/codeforces/round1039/problemA.png)

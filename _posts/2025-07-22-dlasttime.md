---
title: Codeforces Round 1037 Problem "This is the Last Time"
date: 2025-07-22
categories: [Codeforces, Round 1037]
tags: [codeforces, coding, competitive programming]
description: Solution for coding problem "This is the Last Time"
---

Link: [https://codeforces.com/contest/2126/problem/D](https://codeforces.com/contest/2126/problem/D)

> 
> Time limit per test: 2 second
> 
> Memory limit per test: 256 megabytes
{: .prompt-info }

## Problem description
You are given n casinos, numbered from 1 to n. Each casino is described by three integers: l<sub>i</sub>, r<sub>i</sub>, and reali (l<sub>i</sub> ≤ real<sub>i</sub> ≤ r<sub>i</sub>). You initially have k coins.

You can play at casino i only if the current number of coins x satisfies l<sub>i</sub> ≤ x ≤ r<sub>i</sub>. After playing, your number of coins becomes reali.

You can visit the casinos in any order and are not required to visit all of them. Each casino can be visited no more than once.

Your task is to find the maximum final number of coins you can obtain.

## Input

The first line contains a single integer t (1 ≤ t ≤ 10<sup>4</sup>) — the number of test cases.

The first line of each test case contains two integers n and k (1 ≤ n ≤ 10<sup>5</sup>, 0 ≤ k ≤ 10<sup>9</sup>) — the number of casinos and the initial number of coins.

This is followed by n lines. In the i-th line, there are three integers l<sub>i</sub>, r<sub>i</sub>, real<sub>i</sub> (0 ≤ l<sub>i</sub> ≤ real<sub>i</sub> ≤ r<sub>i</sub> ≤ 10<sup>9</sup>) — the parameters of the i-th casino.

It is guaranteed that the sum of all n across all test cases does not exceed 10<sup>5</sup>.

## Output

For each test case, output a single integer — the maximum number of coins you can obtain after optimally choosing the order of visiting the casinos.

## Example:

### Input: 
```
5
3 1
2 3 3
1 2 2
3 10 10
1 0
1 2 2
1 2
1 2 2
2 2
1 3 2
2 4 4
2 5
1 10 5
3 6 5
```

### Output:
```
10
0
2
4
5
```

### Note
In the first test case, you can first play at the 2-nd casino. After that, you will have 2 coins. Then you can play at the 1-st casino, and the number of coins will increase to 3. Finally, after playing at the 3-rd casino, you will have 10 coins — this is the maximum possible amount.

In the second test case, you have no money, so you cannot earn more.

In the fourth test case, it is beneficial to play at the 2-nd casino right away and earn 4 coins.

## Approach
If you currently have K coins, you never have to go to a casino (let's say the ith casino) where the real<sub>i</sub> is less than or equal to K. Decreasing the number of coins that you have is never beneficial specifically because real<sub>i</sub> is less than or equal to r<sub>i</sub>. This shows that it is alwasy beneficial to have more coins than less.

Now, knowing that, we can actually see that we just need to sort all casinos by their real values and check each one if we can increase our number of coins. We actually don't care about r<sub>i</sub> because if the number of coins we have is less than the real value of a casino, then the r value is also larger than the number of coins we have. 

Therefore, for each casino (with all casinos ordered so that the real values are in non-decreasing order), we just need to check if the l value of a casino is less than or equal to the number of coins we currently have.

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
        int N, K;
        cin >> N >> K;
        vector<vector<int>> casinos(N, vector<int> (3));
        for(int j = 0; j < N; j++) {
            cin >> casinos[j][1] >> casinos[j][2] >> casinos[j][0];
        }
        sort(casinos.begin(), casinos.end());
        for(int j = 0; j < N; j++) {
            if(K >= casinos[j][1] && K < casinos[j][0]) {
                K = casinos[j][0];
            }
        }
        cout << K << '\n';
    }
    return 0;
}
```

**Lines 1-4:** imported all libraries needed and used the namespace std

**Lines 7-8:** initializes T (test cases) and inputs them in

**Line 9:** starts a for loop for the number of test cases

**Line 10-11:** initializes and inputs in N and K

**Lines 12-15:** intializes a vector (array) called casinos, inputs in all values for each casino and sorts the array based on the real values

**Lines 16-21:** in the ordered array, for each casino, checks if you can increase the number of coins you have. if you can, then it does increase. the code finally prints the final answer

Then, the code continues this process from lines 10-21 for all other test cases.

## Accepted!

![Problem D Accepted](/assets/img/codeforces/round1037/problemD.png)

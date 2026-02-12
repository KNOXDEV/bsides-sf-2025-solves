# soothsayer
Original Prompt:
```
Which came first the dragon or the egg? Guess correctly 30 times in a row.```

I'm not going to write the solution to this one because in order to run a simulation of the server locally,
I would need to set up a Firebase DB to provide the backend for the app / backend server.

What needs to be done here is extremely straightforward to see from the source code when
inspected with `jadx-gui`. The app in question asks you to guess between two random options,
and you need to guess correctly 30 times in a row. However, it does so via a MersenneTwister
prng where the client generates the initial seed and tells the Firebase DB what it is.

```java
    protected void computeChoice(int choice) {
        double number = this.mt.nextDouble();
        int num = (int) Math.floor((number * 1000.0d) + 15.0d);
        if (choice == num % 2) {
            User user = User.getInstance();
            user.score++;
        }
    }
```

Therefore, you only need to write a Python script that communicates with the 
firebase server to set a User object (with seed embedded), simulate the correct
choice 30 times locally, then submit a request to the flag endpoint which 
presumably consults the same Firebase db. 
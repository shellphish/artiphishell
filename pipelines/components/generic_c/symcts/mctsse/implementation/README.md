# Components

1. 1x RabbitMQ server
2. 1x MCTS (master, scheduler)
3. Nx Solver backend
    - input: solver request (solve for new input)
    - ouput: coverage tracer requests (trace new input) -> Coverage Tracer
4. Nx Coverage Tracer backend
    - input: program input files <- Solver
    - output: coverage profile -> MCTS master

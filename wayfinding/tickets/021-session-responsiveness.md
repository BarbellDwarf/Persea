# Session Responsiveness: Profile and Optimize RDP/SSH Latency

## Question

What is the current latency profile for RDP and SSH sessions? Where is time spent between user input and screen update — browser JS, WebSocket, persea proxy, guacd, target server? What low-hanging improvements reduce perceived latency?

## Deliverable

A latency breakdown (browser→WS→persea→guacd→target), each measured or estimated in ms. Then a prioritized list of optimizations: what to change and the expected impact.

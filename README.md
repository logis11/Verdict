```
   ██╗   ██╗███████╗██████╗ ██████╗ ██╗ ██████╗████████╗
   ██║   ██║██╔════╝██╔══██╗██╔══██╗██║██╔════╝╚══██╔══╝
   ██║   ██║█████╗  ██████╔╝██║  ██║██║██║        ██║   
   ╚██╗ ██╔╝██╔══╝  ██╔══██╗██║  ██║██║██║        ██║   
    ╚████╔╝ ███████╗██║  ██║██████╔╝██║╚██████╗   ██║   
     ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═════╝ ╚═╝ ╚═════╝   ╚═╝   
                                 Autonomous Vulnerability Finding
```

# Verdict

## What is it

Verdict is an autonomous vulnerability research pipeline using the Claude Agent SDK.

The main objective of the pipeline is to autonomously identify vulnerabilities that can be clearly verified.

So far, a total of 7 vulnerabilities found through Verdict have been reported to MSRC, and one open source contribution has been made.

The project is still experimental, and it is continuously being developed. 

## Motivation

As AI has been taking a larger role in vulnerability research, I noticed a few recurring problems while using agents for actual research.

### False positives

Manual demonstration or confirmation was almost always required.

This cannot be completely removed, since the final decision should be made by humans. However, there were too many false positives, and repeatedly checking whether they were actually reproducible was time consuming.

One of the main goals of Verdict is to reduce the amount of manual work spent on findings that cannot survive basic verification.

### False negatives

As more capable AI models appear, cheap and obvious vulnerabilities are being found quickly and are becoming increasingly exhausted.

Because of this, finding a new vulnerability often requires more than simply asking an agent, "find me a vulnerability here," especially for widely used and heavily researched targets such as Windows kernel drivers.

The agent needs to keep track of what has already been checked, what remains unexplored, and which previous ideas failed.

### Frequent interruption

Even when an agent is asked to run for a long period of time, I have rarely seen it continue until it reaches a useful conclusion.

Agents often decide that they have finished everything they can do, even when there is still a significant amount of unexplored attack surface.

Verdict was designed so that progress and remaining work are tracked outside of the agent's immediate context, instead of relying only on the agent to decide when the research is finished.

### Hallucinations

There have been a few cases where an agent hallucinated instructions or behavior that did not actually exist in a driver, and then argued that the hallucinated behavior was a vulnerability.

Another problem appears as the context becomes larger. The agent can lose track of what it has already done, which can lead to repeated work, contradictory conclusions, or incorrect assumptions.

Verdict tries to reduce this by keeping research state separately and by verifying claims deterministically where possible.

Verdict was built as an attempt to solve the problems above.

## Prior work

Verdict is not the first project that tries to automate vulnerability research with LLM agents.

Naptime showed that vulnerability research agents become much more useful when they are given an environment where they can inspect, execute, and verify their findings instead of only reasoning about code in text.

There has also been prior work on autonomous binary analysis and vulnerability research agents, where the agent is given tools for navigating binaries, inspecting functions, following references, and validating hypotheses.

RAPTOR provides a similar autonomous vulnerability research workflow, but Verdict was built more around keeping an agent continuously exploring a target, tracking unfinished work externally, and questioning both accepted and rejected findings. Although RAPTOR still has a lot more structure/useful feature, I thought creating my own pipeline is meaningful by itself.

The main idea is not that an LLM can find vulnerabilities by itself. The idea is to structure the surrounding process so that the agent can continue exploring while bad findings are filtered out as much as possible.

## Structure

The current structure is roughly:

```text
analyst
   |
   v
candidate
   |
   +--> refuter
   |
   +--> interrogator / escalator
   |
   v
adjudicator
   |
   v
final state
```

The analyst performs the main vulnerability research and records candidates and explored surfaces.

Research state is stored separately so that the agent does not need to remember everything inside a single context window.

The refuter tries to disprove a candidate.

The interrogator checks whether rejected candidates were rejected for the right reason.

The escalator is used when a candidate exists but the actual security impact is unclear.

The adjudicator takes the results from these stages and decides the final state of the candidate.

Some parts of the verification are intentionally not handled by an LLM. If a claim can be checked directly from the binary or from other deterministic evidence, Verdict tries to verify it directly instead of asking another agent whether it agrees.

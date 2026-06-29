# 👾 Personal Rust Learning Lab

Welcome to my personal **Rust Learning Lab**. This entire workspace is dedicated exclusively to learning, building, and deploying Rust applications locally. 

**Note:** This repository is a private, local development environment. It will *never* be uploaded to GitHub or deployed to external production servers. It is my personal sandbox for mastering the Rust programming language, experimenting with AI, and building high-performance local tools.

---

## 🛠️ Workspace Philosophy

This lab serves as the centralized development hub for all my Rust projects. The primary goals of this workspace are:
- **Learning & Experimentation**: A safe environment to test new crates, learn memory management, and experiment with advanced Rust paradigms.
- **Local Deployment**: Building tools that run locally to automate tasks, explore edge AI, and monitor system security.
- **Compiler-Driven Development**: Utilizing Rust's strict compiler to write memory-safe, reliable software.

---

## 🏗️ Active Projects Catalog

Below is a detailed summary of all the projects currently developed in this workspace. These tools are designed to be fast, secure, and helpful for various tasks ranging from artificial intelligence to system security.

### 1. Aegis (The Forensic Sentinel)
**What it does:** Aegis is a high-speed security guard for computer systems. It constantly monitors computer activity and logs to detect advanced cyber attacks and suspicious behavior as it happens.
**What it is good for:** It is perfect for securing sensitive environments, automatically catching hackers, and ensuring that computer systems comply with strict federal security rules. It includes a built-in visual dashboard so security teams can see what is happening in real-time.

### 2. Chandrian
**What it does:** Think of Chandrian as a health inspector and driving examiner for other AI programs. It stress-tests AI agents by throwing tricky scenarios at them to see if they break the rules, leak private passwords, or make things up (hallucinate).
**What it is good for:** It ensures that any AI tool a company uses is safe, reliable, and trustworthy before it is allowed to handle sensitive data or interact with real users.

### 3. Gemini CLI (gemini-rs)
**What it does:** A lightning-fast chat tool that lives directly inside your computer's terminal (command line). It lets you talk directly to Google's Gemini AI without needing to open a web browser.
**What it is good for:** It is incredibly useful for programmers and power users who want to ask the AI questions, fix errors, or generate computer commands instantly while they are already working in their terminal.

### 4. Neuroweave
**What it does:** Neuroweave acts as a smart traffic cop for AI coding requests. When a developer asks the AI to do a simple, repetitive task (like formatting code), Neuroweave catches the request and does it instantly on the local computer. 
**What it is good for:** It saves time and money. By handling easy tasks locally in milliseconds, it prevents the system from wasting time and resources sending simple questions to an expensive cloud AI. Complex questions are still passed to the main AI for deep thinking.

### 5. Obsidian MCP Server
**What it does:** This is a secure bridge that connects AI assistants to Obsidian (a popular personal note-taking application). 
**What it is good for:** It allows AI tools to safely read your personal notes, search through your knowledge base, and write new ideas directly into your notebooks, all while keeping your data private and local to your computer.

### 6. Omnicrawl
**What it does:** Omnicrawl is an automated web research and website-building robot. It hunts down local business websites, reads them to extract useful information, filters out fake or non-local businesses, and then automatically builds highly optimized web pages for them.
**What it is good for:** It is fantastic for automatically generating high-quality business directories and generating leads without requiring human researchers to manually read thousands of websites.

### 7. PocketGemma & PocketGemma4
**What it does:** These are tiny, self-contained applications that let you run a powerful AI model (Gemma 2) entirely on your local computer, with zero need for an internet connection.
**What it is good for:** Perfect for situations where privacy is critical or internet access is unavailable (like working on an airplane or in a secure facility). It includes a beautiful chat interface and protects your computer from crashing by intelligently managing memory.
**Hardware Requirements:** Running local AI models is extremely demanding. This application requires a modern, high-performance computer with a significant amount of RAM (ideally 16GB+). It will struggle or fail to run on older or low-end laptops.

### 8. Pocket LLaMA
**What it does:** Similar to PocketGemma, Pocket LLaMA is an all-in-one application that lets you run various popular AI models (from the LLaMA family) locally on your computer.
**What it is good for:** It is designed to be highly portable—you can even run it directly from a USB thumb drive. It's ideal for bringing powerful, offline AI capabilities to any computer instantly without complex installations.
**Hardware Requirements:** Like PocketGemma, running these models locally requires strong hardware. A modern processor and plenty of RAM (16GB+) are required for a smooth experience. It is not recommended for low-end or aging laptops.

### 9. Antigravity Core MCP Server
**What it does:** This is a "Swiss Army knife" tool that bundles several helpful developer services into one tiny package. It includes tools for scraping websites, checking code for errors, analyzing software packages, and injecting helpful code templates.
**What it is good for:** It drastically simplifies the workspace by combining many different utilities into a single, blazing-fast program, helping developers write better code more efficiently.

### 10. Sleipnir
**What it does:** Sleipnir is a lightning-fast, terminal-based "Human-on-the-Loop" orchestration dashboard and control runtime. It acts as a centralized policy clearinghouse that intercepts, evaluates, and optionally blocks high-risk actions from autonomous AI agents before they execute on the host system.
**What it is good for:** Perfect for safely running autonomous agents locally. It provides real-time telemetry, lets operators instantly freeze agent execution, and enforces strict security policies (Allow, Verify, Deny) with sub-millisecond latency via sandboxed local IPC channels.

---

## 🧹 Workspace Management

To keep developer memory overhead low and compile speeds high, the workspace leverages a unified build system:
*   **Unified Build Cache**: All active sub-projects write their build outputs to the root `target/` folder, preventing redundant crate compilation.
*   **Run Cleanups**: If you ever need to purge the entire workspace build cache to free up hard drive space, simply run `cargo clean`.

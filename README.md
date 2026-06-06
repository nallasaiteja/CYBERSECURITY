# 🛡️ CyberShield AI — Next-Gen Security Intelligence Hub

**CyberShield AI** is an advanced, hackathon-ready cybersecurity management platform. It combines real-time threat monitoring, heuristic AI-driven phishing analysis, automatic system alerts, and comprehensive role-based operator controls into a single unified workspace.

---

## 🚀 Key Features

*   **AI Phishing Sandbox**: Performs real-time evaluation of URLs, Emails, and SMS content. It uses pattern matching and heuristic algorithms to generate human-readable verdicts, risk scores, confidence ratings, and actionable response recommendations.
*   **Real-time Threat Monitoring**: Autonomously logs security indicators such as brute-force attacks, multiple login attempt patterns, and unauthorized network scans, all synced in real-time.
*   **Security Alert Engine**: Automatically fires system alerts when failed logins exceed 5 within 10 minutes, when phishing risk scores cross 80, or when repeated suspicious activity is logged.
*   **Administrative Control Hub**: A tabbed glassmorphic space where verified Admins can review all operators, suspend accounts, delete users, resolve threats, and export reports to CSV or JSON formats.
*   **Role-Based Security & Real-time Session Lock**: Features routing guards, login checks, and database RLS constraints. If an operator is suspended, their active session is terminated instantly via Postgres Realtime subscriptions.

---

## 🛠️ Technology Stack

*   **Frontend**: React (TypeScript), Vite, React Router DOM
*   **Styling**: Custom CSS (supporting Dark/Light theme variables & mobile breakpoints)
*   **Backend & Database**: Supabase (PostgreSQL, row-level security, functions, triggers, and realtime listeners)
*   **Icons**: Lucide React
*   **Hosting**: Vercel

---

## 💾 Local Setup Guide

### 1. Clone & Install Dependencies
Ensure you have Node.js installed on your machine. In your terminal, run:

```bash
# Install package dependencies
npm install
```

### 2. Configure Environment Variables
Create a `.env.local` file in the root of your project directory and add your Supabase credentials:

```env
VITE_SUPABASE_URL=https://your-project-id.supabase.co
VITE_SUPABASE_ANON_KEY=your-anon-public-key
```

### 3. Start Development Server
Start Vite's local hot-reloading server:

```bash
npm run dev
```
Open **[http://localhost:5173](http://localhost:5173)** in your browser to view the application.

> [!TIP]
> **Testing Admin Privileges**: To register a new administrator account on the signup page, select the **Security Admin (Admin)** option and enter the authorization key: `CYBER_SHIELD_2026`. This restricts unauthorized users from self-elevating their access in production.

---

## 🗄️ Supabase Database Setup

Initializing the database backend takes just a single step:

1. Open your **[Supabase SQL Editor](https://supabase.com/dashboard/project/kiyyqfywpxafckvggpls/sql/new)**.
2. Create a **New Query**.
3. Copy the contents of the consolidated database migration script: **[supabase/schema_complete.sql](file:///c:/Users/Mohan/OneDrive/Desktop/CYBER%20SECURITY/supabase/schema_complete.sql)**.
4. Paste the SQL query into the Supabase editor and click **Run**.

This query automatically sets up:
*   All required database structures (`profiles`, `phishing_scans`, `failed_logins`, `threat_logs`, `alerts`, `threat_alerts`).
*   Role validation triggers that block normal users from altering authorization clearance levels.
*   Security definer functions for safe administrative deletions.
*   RLS policies restricting all lists to authenticated operators and admin panels to Admins.
*   Pre-populated dummy datasets for logs and metrics.

---

## 🌐 Production Deployment

### 1. Backend Hosting (Supabase)
The database runs completely on Supabase cloud. Simply configure the schema as detailed in the Database Setup section.

### 2. Frontend Hosting (Vercel)
The application includes a [vercel.json](file:///c:/Users/Mohan/OneDrive/Desktop/CYBER%20SECURITY/vercel.json) file configured to enable correct Single Page Application (SPA) routing:

*   Add your project directory to Vercel.
*   Configure the project Build Command: `npm run build` and Output Directory: `dist`.
*   Add the two environment variables `VITE_SUPABASE_URL` and `VITE_SUPABASE_ANON_KEY` to your Vercel Project Settings.
*   Click **Deploy**.

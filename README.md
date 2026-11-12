# 🔥 Spicyhub — B2B SaaS Restaurant OS Platform

A fullstack **B2B SaaS Restaurant Platform** cloned from [eatburst.com](https://eatburst.com/) with complete **Spicyhub** branding, built with an Express.js backend, an embedded **SQLite database**, a live operational **Restaurant OS Workspace** (for restaurant tenants), and a dedicated, unlinked **B2B SaaS Superadmin Console** (for the Spicyhub platform founder).

---

## 🚀 Quick Start

### 1. Install & Start Server
```bash
npm install
npm start
```
> For auto-reloading during development: `npm run dev`

### 2. Portals Architecture
| Portal | URL | Audience | Description |
|---|---|---|---|
| **Marketing Website** | [http://localhost:3000](http://localhost:3000) | Public | Main landing page with working 7-day trial lead modal |
| **Tenant Restaurant OS** | [http://localhost:3000/dashboard](http://localhost:3000/dashboard) | Restaurant Staff | Operational POS billing, KDS kitchen tickets, floor tables, and real-time chef stock audits for a specific restaurant tenant |
| **SaaS Superadmin Console** | [http://localhost:3000/admin](http://localhost:3000/admin) | **Spicyhub Founder** | **Private & Unlinked**: B2B customer accounts, 7-day trial applications, MRR/ARR growth metrics, plan packaging, and global deployment staging |

---

## 💼 B2B SaaS Superadmin Capabilities

### 1. 📋 Inbound 7-Day Trial Applications Pipeline
Captures every prospective restaurant brand that submits via the website modal:
> **"YOUR 7-DAY TRIAL STARTS HERE — Meet your new restaurant OS."**
- Stored fields: Applicant Name, Restaurant Brand, City, Number of Outlets, Work Email, Phone, Submission Timestamp.
- Status management: `New Inbound`, `Contacted`, `Trial Active`, `Closed`.
- **1-Click Workspace Provisioning**: Clicking `🚀 Provision` automatically converts the applicant into an active 7-day tenant workspace.
- Export all pipeline data to **CSV**.

### 2. 🏢 B2B Tenant Restaurants Management
Oversee all client restaurants subscribed to the Spicyhub platform:
- Tenant Restaurant Name, Owner Contact, City, Outlets Deployed, Active Subscription Plan, Monthly Fee (MRR), Account Status (`Active`, `Trial Active`, `Suspended`).
- Provision new restaurant accounts with custom outlet boundaries.

### 3. 💼 SaaS Financials & Recurring Revenue Analytics
- Real-time **Monthly Recurring Revenue (MRR)** and **Annual Run Rate (ARR)**.
- Average Revenue Per User (ARPU).
- Outlets growth rate across India.

### 4. 💳 B2B Plans & Pricing Packaging
- **Starter POS**: ₹1,999/mo (1 Outlet)
- **Pro Multi-Outlet**: ₹4,999/mo (2–5 Outlets)
- **Enterprise Cloud**: ₹12,999/mo (6+ Outlets / Unlimited)

### 5. 📢 Global Broadcast & Staging Deployment
- Draft announcements or system maintenance notes staged in draft mode.
- One-click **`🚀 Publish Platform Update to All Tenants`** pushes live broadcasts to all tenant restaurant POS terminals simultaneously.

---

## 🍽️ Tenant Operational Workspace (`/dashboard`)
Designed specifically for floor staff, cashiers, and kitchen chefs of a client restaurant:
- **POS Billing & Menu Catalog**: Add/edit dishes, manage prices, and choose between automated digital e-bills (with customer email) or hardcopy printing.
- **Floor & Tables**: Add/remove dining stations (T01–T11+) and adjust seating capacity.
- **Kitchen Display System (KDS)**: Step-by-step cooking workflow.
- **Real-Time Chef Audits**: Kitchen staff can edit current stock levels in real time to alert owners when reorders are necessary.

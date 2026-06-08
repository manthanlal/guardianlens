# 🔷 Azure + Foundry IQ Setup Guide

Follow these steps to connect GuardianLens to Microsoft Foundry IQ.

---

## Step 1 — Create Azure Account
1. Go to https://azure.microsoft.com/free
2. Click **"Start free"** — you get $200 free credits
3. Sign in with your Microsoft account

---

## Step 2 — Create a Resource Group
1. Go to https://portal.azure.com
2. Search **"Resource groups"** in the top bar
3. Click **"+ Create"**
4. Fill in:
   - **Subscription**: your subscription
   - **Resource group name**: `guardianlens-rg`
   - **Region**: East US (or nearest to you)
5. Click **"Review + create"** → **"Create"**

---

## Step 3 — Create Azure AI Foundry Project
1. Go to https://ai.azure.com
2. Click **"+ New project"**
3. Fill in:
   - **Project name**: `guardianlens`
   - **Hub**: Create new hub → name it `guardianlens-hub`
   - **Resource group**: `guardianlens-rg`
4. Click **"Create"**
5. Wait ~2 minutes for deployment

---

## Step 4 — Get Your Endpoint
1. Inside your Foundry project, go to **"Settings"**
2. Copy the **"Project endpoint"** URL
3. It looks like: `https://guardianlens.eastus.api.azureml.ms`
4. Paste it as `FOUNDRY_IQ_ENDPOINT` in your `.env`

---

## Step 5 — Create a Service Principal (API credentials)
Run these in Azure Cloud Shell (click the `>_` icon in Azure Portal):

```bash
# Create service principal
az ad sp create-for-rbac --name "guardianlens-sp" --role contributor \
  --scopes /subscriptions/YOUR_SUBSCRIPTION_ID/resourceGroups/guardianlens-rg

# It outputs JSON like:
# {
#   "appId": "xxx",        ← this is AZURE_CLIENT_ID
#   "password": "xxx",     ← this is AZURE_CLIENT_SECRET
#   "tenant": "xxx"        ← this is AZURE_TENANT_ID
# }
```

---

## Step 6 — Update Your .env File

```env
AZURE_TENANT_ID=paste-tenant-here
AZURE_CLIENT_ID=paste-appId-here
AZURE_CLIENT_SECRET=paste-password-here
FOUNDRY_IQ_ENDPOINT=paste-endpoint-here
FOUNDRY_IQ_PROJECT_NAME=guardianlens
```

---

## Step 7 — Verify Connection

```bash
# With server running:
curl http://localhost:8000/foundry/status
```

You should see:
```json
{
  "configured": true,
  "status": "connected",
  "mode": "Microsoft Foundry IQ"
}
```

---

## ✅ Done! GuardianLens now uses Foundry IQ for grounded threat intelligence.

> **Note**: Until Azure is set up, GuardianLens runs in **fallback mode** using
> its local knowledge base. All features work — Foundry IQ just adds
> real-time grounded citations to threat explanations.

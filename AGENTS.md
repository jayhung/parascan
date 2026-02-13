# devmetrics - AI Agent Guide

This file provides context for AI agents working with the devmetrics project.

## Project Overview

A Next.js dashboard for tracking and visualizing development metrics from GitHub repositories. Uses SQLite for local storage and the GitHub API for data synchronization.

## Tech Stack

- **Framework**: Next.js 16 with App Router
- **Language**: TypeScript
- **Database**: SQLite (better-sqlite3)
- **UI**: React with Tailwind CSS, Radix UI components
- **Charts**: Recharts
- **API**: GitHub REST API (@octokit/rest)

## Project Structure

```
agents/
└── plans/                # project plans and roadmap

src/
├── app/
│   ├── api/              # API routes
│   │   ├── metrics/      # fetch metrics data
│   │   ├── repos/        # repository management
│   │   └── sync/         # GitHub sync operations
│   ├── config/           # configuration page
│   ├── layout.tsx        # root layout
│   └── page.tsx          # main dashboard
├── components/
│   ├── charts/           # visualization components
│   ├── ui/               # reusable UI components (Radix-based)
│   └── sync-console.tsx  # sync status display
└── lib/
    ├── db.ts             # SQLite database operations
    ├── github.ts         # GitHub API client
    ├── metrics.ts        # metrics calculation logic
    └── utils.ts          # utility functions

cache/
└── config.json           # persisted configuration (gitignored)
```

## Coding Conventions

### TypeScript
- use strict typing, avoid `any`
- prefer interfaces for object shapes
- use type inference where obvious

### React/Next.js
- functional components only
- use server components by default, 'use client' when needed
- API routes in `src/app/api/`
- route handlers return `NextResponse.json()`

### Code Style
- comments: start lowercase unless multi-line paragraph
- prefer concise, readable code
- extract reusable logic to `lib/`

### Database
- SQLite operations in `lib/db.ts`
- use prepared statements for queries
- handle database errors gracefully

### GitHub Integration
- API client in `lib/github.ts`
- respect rate limits
- cache configuration in `cache/config.json`

## Key Files

- `lib/db.ts`: database schema and queries
- `lib/github.ts`: GitHub API integration
- `lib/metrics.ts`: metrics calculation and aggregation
- `src/app/api/sync/route.ts`: sync endpoint for fetching GitHub data
- `src/app/config/page.tsx`: configuration UI

## Development

**Package Manager**: Always use `yarn`, never `npm`

```bash
yarn dev          # start dev server on port 4000
yarn build        # production build
yarn lint         # run ESLint
yarn add <pkg>    # install dependencies
```

## Environment

- `.env.local` for GitHub token (see `.env.local.example`)
- runs on port 4000 by default

## Common Tasks

- **Adding metrics**: update `lib/metrics.ts` and corresponding chart components
- **New API routes**: create in `src/app/api/`
- **UI components**: add to `src/components/ui/` if reusable
- **Database changes**: modify schema and migrations in `lib/db.ts`

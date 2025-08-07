#!/bin/bash
echo "DATABASE_URL: $DATABASE_URL"
export DATABASE_URL=$DATABASE_URL
npx prisma generate --schema=prisma/schema.prisma
exec "$@"

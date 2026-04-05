import express from 'express';
import cookieParser from 'cookie-parser';
import path from 'path';

import authRoutes from './routes/auth';
import teamRoutes from './routes/teams';
import principalRoutes from './routes/principals';
import policyRoutes from './routes/policies';
import dashboardRoutes from './routes/dashboard';
import billingRoutes from './routes/billing';
import integrationRoutes from './routes/integrations';
import apiKeyRoutes from './routes/api-keys';
import exportRoutes from './routes/export';

const app = express();
const PORT = parseInt(process.env.PORT || '8080', 10);

app.use(express.json());
app.use(cookieParser());

// Static frontend
app.use(express.static(path.join(__dirname, 'public')));

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/teams', teamRoutes);
app.use('/api/principals', principalRoutes);
app.use('/api/policies', policyRoutes);
app.use('/api/dashboard', dashboardRoutes);
app.use('/api/billing', billingRoutes);
app.use('/api/integrations', integrationRoutes);
app.use('/api/api-keys', apiKeyRoutes);
app.use('/api/export', exportRoutes);

// SPA fallback
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`HDP Platform running on port ${PORT}`);
});

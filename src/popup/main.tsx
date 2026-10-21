import { createRoot } from 'react-dom/client';
import { App } from '@/ui/App';
import '@/ui/styles.css';

createRoot(document.getElementById('root') as HTMLElement).render(<App mode="popup" />);

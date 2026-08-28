/**
 * Analyzer barrel. Importing this registers every lane into the framework
 * (mirrors Python's `import app.analyzers`). API routes import from here.
 */
import './m2_headers';
import './m3_auth';
import './m4_content';
import './m5_network';
import './m6_domain';
import './m7_graph';
import './m8_footprint';

export { runAll, registry } from './base';

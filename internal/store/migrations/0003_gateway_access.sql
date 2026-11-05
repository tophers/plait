-- TCP ports on the gateway host itself that connected clients may reach
-- through the tunnel, as a canonical comma-separated list ('' for none).
ALTER TABLE sites ADD COLUMN gateway_tcp_ports TEXT NOT NULL DEFAULT '';

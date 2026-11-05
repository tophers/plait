# Plait overview

Plait gives your phone or laptop secure access to several separate networks
at once, such as your home, a cabin, and a family member's house, using one
WireGuard tunnel. You manage who can reach what from a small web
application, and each network enforces those decisions on its own gateway.

## The problem

WireGuard is fast, simple, and well supported on phones, but it treats every
network as a separate setup. If you want to reach three sites, the usual
answer is three keys, three addresses, and three tunnels on the phone, and
most phones run only one VPN tunnel at a time. You end up switching tunnels
by hand, or stitching configurations together and hoping the addresses,
routes, and keys all line up. Every change means editing files on each
gateway and on every device, and removing someone's access means remembering
everywhere they had it.

Plait replaces that with one identity per device and one place to manage it.

## The idea

Each device gets **one key and one address** that it keeps everywhere. Its
single WireGuard profile lists every site it may reach. When the phone opens
an address on the cabin's network, WireGuard sends that traffic straight to
the cabin. When it opens something at home, the traffic goes straight home.
One tunnel serves all of them at the same time.

Only traffic for those sites' networks goes through the tunnel. Ordinary
internet use from the phone goes out as it normally would.

## The three pieces

```
                    Controller (plaitd)
          web UI · records who may reach what
              /                         \
     asks for its settings        asks for its settings
            /                             \
     Home gateway                    Cabin gateway
     (plait-agent)                   (plait-agent)
     home network                    cabin network
            \                             /
              direct WireGuard connections
                           |
                      your phone
               one profile, one address
```

- **The controller** is the one place you make changes. It runs the web
  application where you add sites and devices and decide which device may
  reach which site. It keeps that record and turns it into exact settings
  for each gateway and each device. It never carries your network traffic.
  If it goes offline, existing connections keep working.

- **A gateway agent** runs on a Linux machine at each site. It regularly asks
  the controller for that site's current settings and applies them locally:
  the WireGuard peers, the routes back to each device, and the firewall rules
  that limit devices to the networks they were granted. It keeps enforcing
  the last settings it received even if it can't reach the controller.

- **Devices** are ordinary phones and computers running the standard
  WireGuard app. Nothing extra is installed on them. They get their settings
  by scanning a QR code or importing a file.

## Everyday use

**Adding a device.** In the web UI, give the device a name and tick the sites
it should reach. The browser creates the device's key, shows a QR code, and
you scan it with the WireGuard app. Done: the phone can reach those sites,
and each site's gateway picks up the new device on its next check-in.

**Granting or removing access.** Remove a device's access to a site, or
disable the device entirely, and the change goes out to the gateways. The
phone doesn't need to do anything; the gateway simply stops accepting it.
Adding a site to a device works the other way round: the phone needs an
updated profile listing the new site. A device you no longer need can be
deleted once it is disabled and its sites have caught up; its address then
goes to the next new device.

**Changing a device's settings.** Things that live on the phone, such as
which DNS server it uses, its MTU, or the list of sites, need a new profile
on the phone, since devices don't fetch updates themselves. Plait flags any
device whose profile is out of date. **Update profile** issues a fresh key
and shows a new QR code. The device keeps its address and all its access,
and you replace the tunnel on the phone by scanning the code.

**Adding a site.** Create the site in the UI, install the agent on that
site's gateway machine, and enroll it with a one-time token. The gateway
then fetches its settings on its own from then on.

## Security, in plain terms

- **Private keys stay where they belong.** A device's private key is created
  in your browser and goes straight to the phone. The controller never
  receives it, and no page asks you to paste one. Each gateway likewise
  creates and keeps its own key.
- **Every site connection has its own extra secret.** Each device-to-site
  pairing gets a separate preshared key, an extra layer on top of
  WireGuard's encryption. These are stored encrypted on the controller.
- **Access is enforced at each site.** A device can reach only the networks
  it was granted, and devices can't reach each other.
- **The controller is protected.** Administrator logins are rate-limited and
  can require a code from an authenticator app (two-factor authentication).
  Every change is written to an audit log.
- **The controller isn't a single point of failure for traffic.** It hands
  out settings; it doesn't relay connections.

## What Plait deliberately doesn't do

- **Push changes to phones.** Devices don't check in with the controller, so
  profile changes need a fresh QR code or file. Revoking access needs nothing
  from the device.
- **IPv6** inside the tunnel. Tunnel addresses and site networks are IPv4.
- **Full-tunnel VPN.** Plait reaches your sites' networks; it isn't a way to
  route all your internet traffic through home.
- **Connect sites to each other, or devices to each other.** Each device
  talks to sites, and nothing else.
- **Get through every network setup.** Each site needs a WireGuard port that
  devices can reach from the internet, directly or through port forwarding.

## Where to go next

- [README.md](README.md): project status and source layout
- [docs/deploy.md](docs/deploy.md): installing the controller and gateways
- [docs/ui.md](docs/ui.md): what each page of the web UI shows
- [SPEC.md](SPEC.md): the full design, for the technical detail

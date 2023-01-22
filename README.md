# k8s-vpn-firewall

### Access control for k8s services from kube openvpn

Can be used with [ovpn-admin](https://github.com/flant/ovpn-admin)

Software watches for new/deleted pods and services using kubernetes api and also watches for ovpn ccd files using inotify.
And synchronizes ipset/iptables rules on the host machine (or inside the container).

First, set a **static client IP** in Edit routes section
After that, the user can access only the resources described in the list. You can set network in Address/Mask fields.

And also you can set k8s services in description fields, for example
- Grant access to app (or service) with label `app=nginx` in `dev` namespace:  `dev:app=nginx`
- Grant access to all applications (or services) in in `dev` namespace:  `dev:*`
- Grant access to all nginx in all namespaces:  `*:app=nginx`

You can add as many lines as you need and grant access to as many networks, pods and services as you need.
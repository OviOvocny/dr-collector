from typing import Union, List

import click
import time

import resolvers
from datatypes import DNSData


def create_runner(target, measurements):
    def runner(resolver_fn, label):
        times = []
        result = None
        with click.progressbar(range(measurements), label=label, show_pos=True, show_percent=False, show_eta=False) \
                as bar:
            for _ in bar:
                start = time.time()
                try:
                    val = resolver_fn(target)
                except BaseException:
                    bar.finish()
                    click.echo(f'Error resolving {target} with {label}', err=True)
                    return None, None
                end = time.time()
                if result is None:
                    result = val
                times.append(end - start)
        if len(times) == 0:
            return None, None
        avg = sum(times) / len(times)
        return avg, result
    return runner


def print_result(label, avg):
    if avg is None:
        click.echo(f'{label} avg: N/A')
        return
    # print in ms if avg is less than 1s
    if avg < 1:
        click.echo(f'{label} avg: {avg*1000:.2f}ms')
    else:
        click.echo(f'{label} avg: {avg:.3f}s')


@click.command()
@click.argument('domain')
@click.option('--measurements', '-m', type=int, help='Number of measurements to take', default=3)
def benchmark(domain, measurements):
    """Benchmark each resolver for the given domain (measure average time)"""

    # domain measurements
    click.echo("Domain measurements...")
    runner = create_runner(domain, measurements)
    # measure DNS
    dns = resolvers.DNS()
    avg_dns, result_dns = runner(dns.query, 'DNS')
    # get IPs
    dns_data, ips = result_dns if result_dns else (None, None)  # type: Union[DNSData, None], Union[List[str], None]
    # measure domain RDAP
    rdap = resolvers.RDAP()
    avg_rdap, result_rdap = runner(rdap.domain, 'RDAP')
    # measure TLS
    tls = resolvers.TLS()
    avg_tls, result_tls = runner(tls.resolve, 'TLS')

    # IP measurements if we have IPs
    if ips:
        click.echo("IP measurements...")
        runner = create_runner(ips[0], measurements)
        # measure IP RDAP
        avg_ip_rdap, result_ip_rdap = runner(rdap.ip, 'IP RDAP')
        # measure Geo
        geo = resolvers.GeoIP2()
        avg_geo, result_geo = runner(geo.single, 'Geo')
        # measure reputation
        rep = resolvers.NERD()
        avg_rep, result_rep = runner(rep.resolve, 'NERD')
        # measure ICMP
        icmp = resolvers.ICMP()
        avg_icmp, result_icmp = runner(icmp.ping, 'ICMP echo')
        # measure ports
        ports = resolvers.PortScan()
        avg_ports, result_ports = runner(ports.scan, 'Ports')
    else:
        click.echo("No IP measurements, no IPs found")

    # print results
    click.echo("Results:")
    print_result('DNS', avg_dns)
    print_result('RDAP', avg_rdap)
    print_result('TLS', avg_tls)
    if ips:
        print_result('IP RDAP', avg_ip_rdap)  # type: ignore
        print_result('Geo', avg_geo)  # type: ignore
        print_result('NERD', avg_rep)  # type: ignore
        print_result('ICMP echo', avg_icmp)  # type: ignore
        print_result('Ports', avg_ports)  # type: ignore


if __name__ == '__main__':
    benchmark()

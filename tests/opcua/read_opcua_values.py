import asyncio
from asyncua import Client

ENDPOINT = "opc.tcp://192.168.210.211:4840"

# NodeId lấy từ kết quả browse của PLC.
NODES = {
    "Vat_1": 'ns=3;s="Vat 1"',
    "Vat_2": 'ns=3;s="Vat 2"',
    "Vat_3": 'ns=3;s="Vat 3"',

    "CD1": 'ns=3;s="CD1"',
    "CD2": 'ns=3;s="CD2"',
    "CD3": 'ns=3;s="CD3"',
    "Nhap": 'ns=3;s="Nhap"',
    "HienThi": 'ns=3;s="HienThi"',
    "BangTai": 'ns=3;s="BangTai"',
}


async def main() -> None:
    async with Client(url=ENDPOINT, timeout=10) as client:
        print(f"Đã kết nối: {ENDPOINT}\n")

        for name, node_id in NODES.items():
            try:
                node = client.get_node(node_id)
                value = await node.read_value()
                data_type = await node.read_data_type_as_variant_type()

                print(
                    f"{name:12} = {value!r:12} "
                    f"| type={data_type.name:10} "
                    f"| node={node_id}"
                )
            except Exception as exc:
                print(f"{name:12} = [LỖI] {exc}")


if __name__ == "__main__":
    asyncio.run(main())
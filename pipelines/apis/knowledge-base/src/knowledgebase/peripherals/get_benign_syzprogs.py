
import pandas as pd
import logging
from ..clients.neo4j_client import Neo4JServer

from ..settings import *


def main():
    logging.basicConfig(level=logging.INFO)
    logging.info('Started')

    import argparse

    parser = argparse.ArgumentParser(description='Populate the knowledge base with Crash Reports for Syzbot crashes (Using dataset collected by @su3ry)')

    parser.add_argument('neo4j_bolt_url', help='Bolt URL for the Neo4J server')
    parser.add_argument('--neo4j-username', help='Username for the Neo4J server', default='neo4j')
    parser.add_argument('--neo4j-password', help='Password for the Neo4J server', default=AUTH_KEY)
    parser.add_argument('--neo4j-db', help='Database name for the Neo4J server', default='neo4j')


    args = parser.parse_args()

    neo4j_server = Neo4JServer(
        args.neo4j_bolt_url,
        args.neo4j_username,
        args.neo4j_password,
        args.neo4j_db
    )


    query_template = (
        "MATCH (n:SyzProg)-[x:SYZPROG_TRIGGERS_BASICBLOCK]-(m:BasicBlock) "
        "WHERE toInteger(x.commit_epoch) > 1672531200 and  m.function_name CONTAINS '{}' "
        "RETURN n.source as `SyzProg` LIMIT 500"
    )

    pds = []
    func_names = ["sk_psock_verdict_data_ready", "nl80211_set_interface", "exfat_direct_IO", "tipc_nl_bearer_add", "__ip6_tnl_rcv", "ctr_encrypt", "ntfs_list_ea", "raw_getsockopt", "ip_set_create", "ip_set_create", "btintel_read_version", "do_sys_name_to_handle", "geneve_rx", "unix_gc", "unix_gc", "unix_gc", "bio_copy_user_iov", "bio_copy_user_iov", "sk_psock_verdict_data_ready", "llc_ui_sendmsg", "btrfs_dev_replace_by_ioctl", "btrfs_issue_discard", "perf_event_validate_size", "ida_free", "ip6_tnl_parse_tlv_enc_lim", "scomp_acomp_comp_decomp", "squashfs_readahead", "diNewExt", "f2fs_fill_super", "pipe_write", "z_erofs_lz4_decompress_mem", "reiserfs_delete_solid_item", "__cfg80211_bss_update", "dev_watchdog", "fib6_info_release", "dbAdjTree", "f2fs_fill_super", "gfs2_quota_cleanup", "prog_array_map_poke_run", "skb_segment", "fib6_add", "btrfs_qgroup_account_extent", "dns_resolver_preparse", "cfg80211_rfkill_poll", "squashfs_read_data", "ovl_parse_param_lowerdir", "drm_mode_setcrtc", "create_pending_snapshot", "ptp_ioctl", "mptcp_parse_option", "btrfs_ioctl_send", "__tun_chr_ioctl", "ntfs_list_ea", "lbmStartIO", "device_add", "create_monitor_event", "ext4_dio_write_iter", "ntfs_init_from_boot", "device_add", "fill_frame_info", "kcm_sendmsg", "bpf_mprog_attach", "l2tp_ip6_sendmsg", "hdr_find_e", "device_add", "rfkill_fop_open", "device_add", "dm9601_mdio_read", "bpf_mprog_attach", "device_add", "gfs2_permission", "nfc_llcp_register_device", "hci_le_create_big_complete_evt", "btrfs_search_path_in_tree_user", "inherit_group", "nci_activate_target", "ntfs_init_from_boot", "ntfs_fill_super", "fq_pie_timer", "__split_huge_page", "dev_set_hwtstamp_phylib", "do_read_inode", "fl_set_key_cfm", "handshake_nl_done_doit", "do_ip_setsockopt", "xsk_diag_fill", "uclogic_input_configured", "__nilfs_mark_inode_dirty", "ieee80211_probe_client", "dbAllocDmapLev", "iopt_unmap_iova_range", "tcx_uninstall", "__ip_append_data", "exfat_iterate", "hwsim_cloned_frame_received_nl", "gadget_bind", "exfat_iterate", "gsm_cleanup_mux", "ingress_destroy", "do_vmi_align_munmap", "do_vmi_align_munmap", "batadv_netlink_set_mesh", "nilfs_lookup_dirty_data_buffers", "hci_conn_unlink", "truncate_dnode", "diUnmount", "ingress_destroy", "snd_seq_create_port", "f2fs_add_inline_entry", "btrfs_dio_submit_io", "extBalloc", "af_alg_sendmsg", "release_journal_dev", "hash_sendmsg", "map_freeze", "hash_sendmsg", "disk_scan_partitions", "kcm_write_msgs", "alloc_branch", "ath9k_wmi_ctrl_rx", "nilfs_clear_dirty_pages", "scm_pidfd_recv", "sk_ioctl", "btrfs_exclop_balance", "gfs2_evict_inode", "usbtmc_ioctl_request", "nilfs_evict_inode", "get_max_inline_xattr_value_size", "ext4_group_desc_csum", "ext4_xattr_move_to_block", "ext4_xattr_move_to_block", "bit_cursor", "xfs_getbmap", "btrfs_csum_one_bio", "btrfs_exclop_balance", "erofs_xattr_prefixes_init", "hwsim_new_radio_nl", "pl_vendor_req", "tcf_pedit_init", "iommufd_vfio_iommu_get_info", "sisusb_probe", "pause_prepare_data", "ovl_copy_up_tmpfile", "fbcon_set_font", "ext4_rename", "ethtool_set_link_ksettings", "do_mount_setattr", "qdisc_create", "hfs_write_inode", "nl802154_trigger_scan", "cramfs_blkdev_read", "j1939_session_deactivate", "kalmia_send_init_packet", "qrtr_endpoint_post", "qdisc_create", "xfs_qm_dqget_cache_insert", "io_do_iopoll", "taprio_reset", "ila_xlat_nl_cmd_get_mapping", "ext4_xattr_inode_iget", "qrtr_node_lookup", "hwsim_pmsr_report_nl", "btrfs_qgroup_rescan_worker", "fl_change", "l2tp_tunnel_register", "__build_all_zonelists", "j1939_session_deactivate", "con_font_get", "xpad_probe", "sock_recv_mark", "tcindex_set_parms", "io_wq_cancel_tw_create", "drm_crtc_next_vblank_start", "bcm_tx_setup", "io_wq_cancel_tw_create", "generic_shutdown_super", "ath6kl_htc_pipe_rx_complete", "fl_change", "udf_rename", "sctp_sendmsg_to_asoc", "qdisc_create", "fsverity_ioctl_enable", "extent_fiemap", "qdisc_create", "ext2_fill_super", "io_wq_cancel_tw_create", "ieee80211_link_info_change_notify"]

    for func_name in func_names:
        query = query_template.format(func_name)
        df = neo4j_server.execute_query(query, return_type='pd')
        col = pd.Series([func_name]*len(df))
        df['func_name'] = col

        pds.append(df)

    all_df = pd.concat(pds, ignore_index=True)
    print(len(all_df))
    print(all_df)

    all_df = all_df.drop_duplicates(subset='SyzProg', keep='last', ignore_index=True)
    print(len(all_df))
    print(all_df)    

    all_df.to_csv('benign_syzprogs.csv', index=False)
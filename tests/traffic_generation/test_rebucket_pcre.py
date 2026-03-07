from core.models import PcreMatch
from traffic_generation.http_builder import rebucket_pcre_by_flags


def test_rebucket_pcre_same_bucket_does_not_self_append_loop():
    # no flags => pcre_flags_to_bucket returns "other"
    clause = PcreMatch(raw='"/abc/"')
    buckets = {
        "other": [clause],
        "file": [],
        "method": [],
        "uri": [],
        "header": [],
        "body": [],
        "cookie": [],
    }

    moved = rebucket_pcre_by_flags(buckets)

    assert moved["other"] == [clause]
    assert len(moved["other"]) == 1

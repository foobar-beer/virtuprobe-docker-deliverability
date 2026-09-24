# The scanning worker, which is the one a probe talks to. Bound to every interface so the published
# port reaches it.
#
# ⚠️ /checkv2 on the CONTROLLER port (11334) answers 401 Unauthorized, because the controller is the
# admin interface and wants a password. The scanning endpoint is this worker on 11333. Hitting the
# wrong port gives a clean JSON error rather than a score, which reads as a broken request.
bind_socket = "*:11333";

ARG BASE_IMAGE

FROM $BASE_IMAGE

COPY ktrace /bin/ktrace
COPY ktrace_stats /bin/ktrace_stats

ENTRYPOINT ["/bin/ktrace"]

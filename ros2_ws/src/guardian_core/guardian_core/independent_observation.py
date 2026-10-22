"""Conservative source-time validation and two-source recovery observations."""
from dataclasses import dataclass
import math

from .bound_recovery import RecoveryTelemetry


@dataclass(frozen=True)
class IndependentSample:
    received_at: float
    speed: float
    free_distance: float
    odom_at: float
    scan_at: float


class SensorObservationBuffer:
    def __init__(self, max_age=0.5, max_skew=0.15):
        self.max_age, self.max_skew = max_age, max_skew
        self._odom = self._scan = None
        self._odom_stamp = self._scan_stamp = -math.inf
        self._epoch_start = -math.inf

    def reset(self, *, now_ros):
        self._odom = self._scan = None
        self._epoch_start = now_ros

    def _stamp_valid(self, stamp, now_ros, previous):
        return (math.isfinite(stamp) and math.isfinite(now_ros)
            and stamp > previous and stamp >= self._epoch_start
            and 0 <= now_ros - stamp <= self.max_age)

    def observe_odometry(self, *, stamp, received_at, now_ros, frame, child_frame, linear, angular):
        self._odom = None
        if (not self._stamp_valid(stamp, now_ros, self._odom_stamp)
                or frame != "map" or child_frame != "base_link"
                or len(linear) != 3 or len(angular) != 3
                or not all(math.isfinite(x) for x in (*linear, *angular, received_at))):
            return
        # A forward scan cannot certify reverse, lateral or rotating motion.
        if linear[0] < 0 or any(abs(x) > 1e-6 for x in (*angular, linear[1], linear[2])):
            return
        speed = math.hypot(linear[0], linear[1])
        if not math.isfinite(speed):
            return
        self._odom_stamp = stamp
        self._odom = (stamp, received_at, speed)

    def observe_scan(self, *, stamp, received_at, now_ros, frame, angle_min,
                     angle_increment, range_min, range_max, ranges):
        self._scan = None
        if (not self._stamp_valid(stamp, now_ros, self._scan_stamp)
                or frame != "base_scan" or not 1 <= len(ranges) <= 4096
                or not all(math.isfinite(x) for x in
                    (angle_min, angle_increment, range_min, range_max, received_at))
                or angle_increment <= 0 or not 0 <= range_min < range_max):
            return
        last_angle = angle_min + angle_increment * (len(ranges) - 1)
        if angle_min > -0.25 or last_angle < 0.25:
            return
        forward = [value for i, value in enumerate(ranges)
            if abs(angle_min + i * angle_increment) <= 0.4]
        if not forward or not all(math.isfinite(x) and range_min <= x <= range_max for x in forward):
            return
        self._scan_stamp = stamp
        self._scan = (stamp, received_at, min(forward))

    def evaluate(self, *, now_ros, now):
        if self._odom is None or self._scan is None:
            return None
        for stamp, received_at, _ in (self._odom, self._scan):
            if not 0 <= now_ros - stamp <= self.max_age or not 0 <= now - received_at <= self.max_age:
                return None
        if abs(self._odom[0] - self._scan[0]) > self.max_skew:
            return None
        return IndependentSample(min(self._odom[1], self._scan[1]),
            self._odom[2], self._scan[2], self._odom[0], self._scan[0])


def fuse_observations(adapter, independent, *, now, max_age, speed_tolerance=0.03):
    if adapter is None or independent is None:
        return None
    if (not all(math.isfinite(x) for x in (independent.speed, independent.free_distance,
            independent.received_at, adapter.speed, adapter.received_at))
            or adapter.speed < 0 or independent.speed < 0 or independent.free_distance < 0
            or not 0 <= now - independent.received_at <= max_age
            or not 0 <= now - adapter.received_at <= max_age
            or abs(adapter.speed - independent.speed) > speed_tolerance):
        return None
    return RecoveryTelemetry(min(adapter.received_at, independent.received_at),
        max(adapter.speed, independent.speed), independent.free_distance,
        adapter.sensor_fresh, adapter.attack_active, adapter.commands_cleared, adapter.probe_success)


class ObserverSessionTracker:
    """Bind replay watermarks to authenticated boot sessions and live GIDs.

    GIDs delimit sessions; HMAC supplies authentication. Exhausting the bounded
    retired-session set latches a fault instead of allowing an old boot back.
    """
    def __init__(self, max_retired=64):
        self.session, self.gid, self.sequence = "", "", 0
        self.retired = set()
        self.max_retired = max_retired
        self.fault = False

    def accept(self, session, gid, sequence):
        if (self.fault or not gid or not isinstance(session, str) or len(session) != 32
                or any(c not in "0123456789abcdef" for c in session) or sequence <= 0):
            return False
        if session == self.session:
            if gid != self.gid or sequence <= self.sequence:
                return False
        else:
            if session in self.retired or (self.session and gid == self.gid):
                return False
            if self.session:
                if len(self.retired) >= self.max_retired:
                    self.fault = True
                    return False
                self.retired.add(self.session)
            self.session, self.gid = session, gid
        self.sequence = sequence
        return True

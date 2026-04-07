import { useRef, useMemo } from "react";
import { Canvas, useFrame } from "@react-three/fiber";
import { Text3D, Center } from "@react-three/drei";

function GaugeRing({ progress, color, radius, speed, delay = 0 }) {
  const meshRef = useRef();
  const count = 64;
  
  const positions = useMemo(() => {
    const pos = new Float32Array(count * 3);
    for (let i = 0; i < count; i++) {
      const angle = (i / count) * Math.PI * 2;
      pos[i * 3] = Math.cos(angle) * radius;
      pos[i * 3 + 1] = Math.sin(angle) * radius;
      pos[i * 3 + 2] = 0;
    }
    return pos;
  }, [radius]);

  useFrame((state) => {
    if (meshRef.current) {
      meshRef.current.rotation.z = state.clock.elapsedTime * speed + delay;
    }
  });

  const activeSegments = Math.floor((progress / 100) * count);

  return (
    <group ref={meshRef}>
      {positions.map((_, i) => {
        const x = positions[i * 3];
        const y = positions[i * 3 + 1];
        const isActive = i < activeSegments;
        return (
          <mesh key={i} position={[x, y, 0]}>
            <circleGeometry args={[0.03, 8]} />
            <meshBasicMaterial color={isActive ? color : "#2a3040"} transparent opacity={isActive ? 1 : 0.5} />
          </mesh>
        );
      })}
    </group>
  );
}

function CenterScore({ score, size }) {
  return (
    <group>
      <mesh>
        <planeGeometry args={[0.001, 0.001]} />
        <meshBasicMaterial transparent opacity={0} />
      </mesh>
      <Center position={[0, 0, 0.5]}>
        <mesh>
          <planeGeometry args={[0.001, 0.001]} />
          <meshBasicMaterial transparent opacity={0} />
        </mesh>
      </Center>
    </group>
  );
}

function GaugeAnimation({ score }) {
  const groupRef = useRef();
  
  useFrame((state) => {
    if (groupRef.current) {
      groupRef.current.rotation.y = Math.sin(state.clock.elapsedTime * 0.3) * 0.1;
      groupRef.current.rotation.x = Math.cos(state.clock.elapsedTime * 0.2) * 0.05;
    }
  });
  
  const color = score >= 80 ? "#ff4444" : score >= 60 ? "#ff9500" : score >= 40 ? "#ffcc00" : "#00ff9d";
  
  return (
    <group ref={groupRef}>
      <GaugeRing progress={score} color={color} radius={0.6} speed={0.1} />
      <GaugeRing progress={score * 0.8} color={color} radius={0.7} speed={-0.08} delay={1} />
      <GaugeRing progress={score * 0.6} color={color} radius={0.8} speed={0.06} delay={2} />
      
      <mesh position={[0, 0, 0.1]}>
        <circleGeometry args={[0.45, 32]} />
        <meshBasicMaterial color="#0a0b10" transparent opacity={0.8} />
      </mesh>
      
      <mesh position={[0, 0, 0.15]}>
        <ringGeometry args={[0.44, 0.46, 32]} />
        <meshBasicMaterial color={color} transparent opacity={0.3} />
      </mesh>
    </group>
  );
}

export default function ScoreGauge3D({ score, size = 200 }) {
  return (
    <div className="score-gauge-3d" style={{ width: size, height: size }}>
      <Canvas camera={{ position: [0, 0, 2], fov: 50 }}>
        <ambientLight intensity={0.5} />
        <pointLight position={[10, 10, 10]} />
        <GaugeAnimation score={score} />
      </Canvas>
      <div className="gauge-score-text">
        <span>{score}</span>
        <small>/100</small>
      </div>
    </div>
  );
}
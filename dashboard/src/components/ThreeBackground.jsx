import { useRef, useMemo } from "react";
import { Canvas, useFrame } from "@react-three/fiber";
import { Points, PointMaterial } from "@react-three/drei";
import * as random from "maath/random/dist/maath-random.esm";

function ParticleField(props) {
  const ref = useRef();
  const sphere = useMemo(() => random.inSphere(new Float32Array(5000), { radius: 1.5 }), []);
  
  useFrame((state, delta) => {
    ref.current.rotation.x -= delta / 10;
    ref.current.rotation.y -= delta / 15;
  });
  
  return (
    <group rotation={[0, 0, Math.PI / 4]}>
      <Points ref={ref} positions={sphere} stride={3} frustumCulled {...props}>
        <PointMaterial
          transparent
          color="#00ff9d"
          size={0.008}
          sizeAttenuation={true}
          depthWrite={false}
          opacity={0.8}
        />
      </Points>
    </group>
  );
}

function NetworkLines() {
  const ref = useRef();
  
  useFrame((state) => {
    if (ref.current) {
      ref.current.rotation.y = state.clock.elapsedTime * 0.05;
      ref.current.rotation.x = Math.sin(state.clock.elapsedTime * 0.02) * 0.1;
    }
  });
  
  return (
    <mesh ref={ref}>
      <icosahedronGeometry args={[1.2, 1]} />
      <meshBasicMaterial color="#1a0b2e" wireframe transparent opacity={0.3} />
    </mesh>
  );
}

function InnerGlow() {
  const ref = useRef();
  
  useFrame((state) => {
    if (ref.current) {
      ref.current.rotation.y = -state.clock.elapsedTime * 0.1;
    }
  });
  
  return (
    <mesh ref={ref}>
      <icosahedronGeometry args={[0.8, 2]} />
      <meshBasicMaterial color="#00ff9d" wireframe transparent opacity={0.15} />
    </mesh>
  );
}

function CyberGrid() {
  const ref = useRef();
  
  return (
    <gridHelper ref={ref} args={[20, 40, "#00ff9d", "#1a0b2e"]} position={[0, -2, 0]} />
  );
}

export default function ThreeBackground() {
  return (
    <div className="three-background">
      <Canvas camera={{ position: [0, 0, 2], fov: 75 }}>
        <ambientLight intensity={0.5} />
        <ParticleField />
        <NetworkLines />
        <InnerGlow />
        <CyberGrid />
        <fog attach="fog" args={["#0a0b10", 2, 8]} />
      </Canvas>
    </div>
  );
}